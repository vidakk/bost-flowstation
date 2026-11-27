//! HTML to WML conversion for the WAP web proxy.
//!
//! A small tolerant tokenizer turns an HTML (or WML/XHTML) page into a flat list of text, line
//! breaks, links and GET forms, which [`paginate`] then packs into WML decks that each fit one
//! WSP reply. Scripts, styles, images, dropdowns and other markup the radio browsers cannot use
//! are dropped. Every form is sent as GET, whatever its method.

use reqwest::Url;

/// Text kept from a link label or a page title, in characters.
const LINK_TEXT_MAX_CHARS: usize = 60;
const TITLE_MAX_CHARS: usize = 20;
/// Pages kept from one document; the rest is replaced by a note.
const MAX_PAGES: usize = 40;

/// Elements whose whole content is dropped.
const SKIPPED: &[&str] = &["script", "style", "noscript", "select", "svg", "template", "iframe", "object", "canvas", "map"];
/// Elements that start or end a line.
const BLOCKS: &[&str] = &[
    "p", "div", "br", "tr", "table", "ul", "ol", "dl", "dt", "dd", "h1", "h2", "h3", "h4", "h5", "h6", "section", "article",
    "header", "footer", "nav", "main", "aside", "blockquote", "pre", "hr", "card", "center", "address", "figure", "figcaption",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
    Text(String),
    Break,
    Link { href: String, text: String },
    Form(Form),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Form {
    pub action: String,
    pub fields: Vec<Field>,
    pub submit: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Field {
    Text { name: String, value: String },
    Hidden { name: String, value: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Document {
    pub title: String,
    pub items: Vec<Item>,
}

struct Tag {
    name: String,
    end: bool,
    attrs: Vec<(String, String)>,
}

impl Tag {
    fn attr(&self, name: &str) -> Option<&str> {
        self.attrs.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }
}

/// Parse a tag starting at `s[0] == '<'`. Returns the tag (None for comments, doctypes and
/// processing instructions) and the bytes consumed.
fn parse_tag(s: &str) -> (Option<Tag>, usize) {
    if s.starts_with("<!--") {
        let len = s[4..].find("-->").map(|i| i + 7).unwrap_or(s.len());
        return (None, len);
    }
    if s.starts_with("<!") || s.starts_with("<?") {
        return (None, s.find('>').map(|i| i + 1).unwrap_or(s.len()));
    }
    let b = s.as_bytes();
    let mut i = 1;
    let end = b.get(i) == Some(&b'/');
    if end {
        i += 1;
    }
    let name_start = i;
    while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'-' || b[i] == b':') {
        i += 1;
    }
    if i == name_start {
        return (None, 0);
    }
    let name = s[name_start..i].to_ascii_lowercase();
    let mut attrs = Vec::new();
    loop {
        while i < b.len() && (b[i].is_ascii_whitespace() || b[i] == b'/') {
            i += 1;
        }
        if i >= b.len() {
            break;
        }
        if b[i] == b'>' {
            i += 1;
            break;
        }
        let k_start = i;
        while i < b.len() && !b[i].is_ascii_whitespace() && !matches!(b[i], b'=' | b'>' | b'/') {
            i += 1;
        }
        let key = s[k_start..i].to_ascii_lowercase();
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        let mut value = String::new();
        if b.get(i) == Some(&b'=') {
            i += 1;
            while i < b.len() && b[i].is_ascii_whitespace() {
                i += 1;
            }
            match b.get(i) {
                Some(&q) if q == b'"' || q == b'\'' => {
                    let v_start = i + 1;
                    let v_end = s[v_start..].find(q as char).map(|p| v_start + p).unwrap_or(s.len());
                    value = decode_entities(&s[v_start..v_end]);
                    i = (v_end + 1).min(s.len());
                }
                _ => {
                    let v_start = i;
                    while i < b.len() && !b[i].is_ascii_whitespace() && b[i] != b'>' {
                        i += 1;
                    }
                    value = decode_entities(&s[v_start..i]);
                }
            }
        }
        if key.is_empty() {
            i += 1;
        } else {
            attrs.push((key, value));
        }
    }
    (Some(Tag { name, end, attrs }), i)
}

/// Decode character references and the named entities pages commonly use.
pub fn decode_entities(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(pos) = rest.find('&') {
        out.push_str(&rest[..pos]);
        rest = &rest[pos..];
        let semi = rest.bytes().take(12).position(|b| b == b';');
        let decoded = semi.and_then(|end| {
            let name = &rest[1..end];
            let ch = if let Some(num) = name.strip_prefix("#x").or_else(|| name.strip_prefix("#X")) {
                u32::from_str_radix(num, 16).ok().and_then(char::from_u32)
            } else if let Some(num) = name.strip_prefix('#') {
                num.parse::<u32>().ok().and_then(char::from_u32)
            } else {
                Some(match name {
                    "amp" => '&',
                    "lt" => '<',
                    "gt" => '>',
                    "quot" => '"',
                    "apos" => '\'',
                    "nbsp" => ' ',
                    "copy" => '©',
                    "reg" => '®',
                    "mdash" => '-',
                    "ndash" => '-',
                    "hellip" => '…',
                    "lsquo" | "rsquo" => '\'',
                    "ldquo" | "rdquo" => '"',
                    "laquo" => '«',
                    "raquo" => '»',
                    "middot" | "bull" => '*',
                    "deg" => '°',
                    "euro" => '€',
                    _ => return None,
                })
            };
            ch.map(|c| (c, end + 1))
        });
        match decoded {
            Some((c, used)) => {
                out.push(c);
                rest = &rest[used..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// Fold typographic characters to ASCII so they render on old browsers and cost one byte.
fn fold_char(c: char) -> Option<&'static str> {
    Some(match c {
        '\u{a0}' | '\u{2002}'..='\u{200a}' => " ",
        '\u{200b}' | '\u{200c}' | '\u{200d}' | '\u{feff}' => "",
        '\u{2018}' | '\u{2019}' | '\u{201a}' | '\u{2032}' => "'",
        '\u{201c}' | '\u{201d}' | '\u{201e}' | '\u{2033}' => "\"",
        '\u{2010}'..='\u{2015}' | '\u{2212}' => "-",
        '\u{2026}' => "...",
        '\u{2022}' | '\u{00b7}' => "*",
        '\u{00ab}' => "<<",
        '\u{00bb}' => ">>",
        _ => return None,
    })
}

fn push_text(buf: &mut String, raw: &str) {
    for c in decode_entities(raw).chars() {
        let folded;
        let piece = match fold_char(c) {
            Some(f) => f,
            None if c.is_whitespace() => " ",
            None if c.is_control() => continue,
            None => {
                folded = c.to_string();
                folded.as_str()
            }
        };
        for pc in piece.chars() {
            if pc == ' ' {
                if !buf.is_empty() && !buf.ends_with(' ') {
                    buf.push(' ');
                }
            } else {
                buf.push(pc);
            }
        }
    }
}

fn truncate_chars(s: &str, max: usize) -> String {
    let t = s.trim();
    if t.chars().count() <= max {
        return t.to_string();
    }
    let mut out: String = t.chars().take(max.saturating_sub(1)).collect();
    out.push('~');
    out
}

/// Resolve a link target to an absolute http(s) URL, unwrapping DuckDuckGo's result redirect
/// (`//duckduckgo.com/l/?uddg=<target>`) so the radio fetches the target directly.
pub fn resolve_link(base: &Url, href: &str) -> Option<Url> {
    let href = href.trim();
    if href.is_empty() || href.starts_with('#') {
        return None;
    }
    let mut url = base.join(href).ok()?;
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    let is_ddg = url.host_str().is_some_and(|h| h == "duckduckgo.com" || h.ends_with(".duckduckgo.com"));
    if is_ddg && url.path().starts_with("/l/") {
        if let Some(target) = url.query_pairs().find(|(k, _)| k == "uddg").and_then(|(_, v)| Url::parse(&v).ok()) {
            if matches!(target.scheme(), "http" | "https") {
                url = target;
            }
        }
    }
    url.set_fragment(None);
    Some(url)
}

#[derive(Default)]
struct Builder {
    items: Vec<Item>,
    text: String,
}

impl Builder {
    fn flush_text(&mut self) {
        let t = self.text.trim();
        if !t.is_empty() {
            self.items.push(Item::Text(t.to_string()));
        }
        self.text.clear();
    }

    fn brk(&mut self) {
        self.flush_text();
        if !self.items.is_empty() && self.items.last() != Some(&Item::Break) {
            self.items.push(Item::Break);
        }
    }

    fn push(&mut self, item: Item) {
        self.flush_text();
        self.items.push(item);
    }

    fn finish(mut self) -> Vec<Item> {
        self.flush_text();
        while self.items.last() == Some(&Item::Break) {
            self.items.pop();
        }
        self.items
    }
}

/// Parse a page into a [`Document`]. `base` is the page's final URL, used to resolve links.
pub fn parse_html(html: &str, base: &Url) -> Document {
    let mut b = Builder::default();
    let mut title = String::new();
    let mut in_title = false;
    let mut skip: Option<String> = None;
    let mut link: Option<(Url, String, String)> = None; // target, text, image alt
    let mut form: Option<Form> = None;
    let mut textarea: Option<(String, String)> = None;

    let mut i = 0;
    while i < html.len() {
        let rest = &html[i..];
        if !rest.starts_with('<') {
            let end = rest.find('<').unwrap_or(rest.len());
            let chunk = &rest[..end];
            i += end;
            if skip.is_some() {
                continue;
            }
            if in_title {
                push_text(&mut title, chunk);
            } else if let Some((_, value)) = textarea.as_mut() {
                value.push_str(&decode_entities(chunk));
            } else if let Some((_, text, _)) = link.as_mut() {
                push_text(text, chunk);
            } else {
                push_text(&mut b.text, chunk);
            }
            continue;
        }
        let (tag, used) = parse_tag(rest);
        if used == 0 {
            // A stray '<' is text.
            if skip.is_none() && !in_title {
                push_text(link.as_mut().map(|l| &mut l.1).unwrap_or(&mut b.text), "<");
            }
            i += 1;
            continue;
        }
        i += used;
        let Some(tag) = tag else { continue };

        if let Some(name) = &skip {
            if tag.end && tag.name == *name {
                skip = None;
            }
            continue;
        }
        if !tag.end && SKIPPED.contains(&tag.name.as_str()) {
            skip = Some(tag.name.clone());
            continue;
        }

        match (tag.name.as_str(), tag.end) {
            ("title", false) => in_title = true,
            ("title", true) => in_title = false,
            ("a", false) => {
                if let Some((url, text, alt)) = link.take() {
                    finish_link(&mut b, url, text, alt);
                }
                if let Some(url) = tag.attr("href").and_then(|h| resolve_link(base, h)) {
                    b.flush_text();
                    link = Some((url, String::new(), String::new()));
                }
            }
            ("a", true) => {
                if let Some((url, text, alt)) = link.take() {
                    finish_link(&mut b, url, text, alt);
                }
            }
            ("img", false) => {
                if let (Some((_, _, alt)), Some(a)) = (link.as_mut(), tag.attr("alt")) {
                    alt.push_str(a);
                }
            }
            ("form", false) => {
                if let Some(f) = form.take() {
                    finish_form(&mut b, f);
                }
                b.brk();
                let action = tag
                    .attr("action")
                    .and_then(|a| base.join(a).ok())
                    .unwrap_or_else(|| base.clone());
                if matches!(action.scheme(), "http" | "https") {
                    let mut action = action;
                    action.set_fragment(None);
                    form = Some(Form { action: action.to_string(), fields: Vec::new(), submit: String::new() });
                }
            }
            ("form", true) => {
                if let Some(f) = form.take() {
                    finish_form(&mut b, f);
                }
                b.brk();
            }
            ("input", false) => {
                if let Some(f) = form.as_mut() {
                    let name = tag.attr("name").unwrap_or("").to_string();
                    let value = tag.attr("value").unwrap_or("").to_string();
                    match tag.attr("type").unwrap_or("text").to_ascii_lowercase().as_str() {
                        "hidden" if !name.is_empty() => f.fields.push(Field::Hidden { name, value }),
                        "text" | "search" | "email" | "url" | "tel" | "number" if !name.is_empty() => {
                            f.fields.push(Field::Text { name, value })
                        }
                        "submit" | "image" if f.submit.is_empty() => {
                            f.submit = if value.is_empty() { "Go".into() } else { value };
                        }
                        _ => {}
                    }
                }
            }
            ("textarea", false) => {
                if form.is_some() {
                    textarea = Some((tag.attr("name").unwrap_or("").to_string(), String::new()));
                }
            }
            ("textarea", true) => {
                if let (Some((name, value)), Some(f)) = (textarea.take(), form.as_mut()) {
                    if !name.is_empty() {
                        f.fields.push(Field::Text { name, value: value.trim().to_string() });
                    }
                }
            }
            ("li", false) => {
                b.brk();
                b.text.push_str("* ");
            }
            ("td", false) | ("th", false) => {
                if !b.text.is_empty() && !b.text.ends_with(' ') {
                    b.text.push(' ');
                }
            }
            (name, _) if BLOCKS.contains(&name) => {
                if link.is_none() {
                    b.brk();
                }
            }
            _ => {}
        }
    }
    if let Some((url, text, alt)) = link.take() {
        finish_link(&mut b, url, text, alt);
    }
    if let Some(f) = form.take() {
        finish_form(&mut b, f);
    }

    let title = if title.trim().is_empty() { base.host_str().unwrap_or("Page").to_string() } else { title };
    Document { title: truncate_chars(&title, TITLE_MAX_CHARS), items: b.finish() }
}

fn finish_link(b: &mut Builder, url: Url, text: String, alt: String) {
    let label = if !text.trim().is_empty() {
        text
    } else if !alt.trim().is_empty() {
        alt
    } else {
        return;
    };
    b.push(Item::Link { href: url.to_string(), text: truncate_chars(&label, LINK_TEXT_MAX_CHARS) });
}

fn finish_form(b: &mut Builder, mut f: Form) {
    if !f.fields.iter().any(|x| matches!(x, Field::Text { .. })) && f.submit.is_empty() {
        return;
    }
    if f.submit.is_empty() {
        f.submit = "Go".into();
    }
    f.submit = truncate_chars(&f.submit, 20);
    b.push(Item::Form(f));
}

/// Escape text for WML element content. `$` starts a WML variable, so it is doubled.
pub fn wml_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '$' => out.push_str("$$"),
            _ => out.push(c),
        }
    }
    out
}

/// Escape a WML attribute value.
pub fn wml_attr(s: &str) -> String {
    wml_text(s).replace('"', "&quot;").replace('\'', "&apos;")
}

fn render_form(f: &Form) -> String {
    let mut inputs = String::new();
    let mut posts = String::new();
    let mut var = 0;
    for field in &f.fields {
        match field {
            Field::Text { name, value } => {
                inputs.push_str(&format!("<input name=\"v{var}\" value=\"{}\"/>", wml_attr(value)));
                posts.push_str(&format!("<postfield name=\"{}\" value=\"$(v{var})\"/>", wml_attr(name)));
                var += 1;
            }
            Field::Hidden { name, value } => {
                posts.push_str(&format!("<postfield name=\"{}\" value=\"{}\"/>", wml_attr(name), wml_attr(value)));
            }
        }
    }
    format!(
        "{inputs}<anchor>{}<go href=\"{}\" method=\"get\">{posts}</go></anchor>",
        wml_text(&f.submit),
        wml_attr(&f.action)
    )
}

/// Render one item. Text is returned whole and split by the caller.
fn render_item(item: &Item) -> String {
    match item {
        Item::Text(t) => wml_text(t),
        Item::Break => "<br/>".to_string(),
        Item::Link { href, text } => format!("<a href=\"{}\">{}</a>", wml_attr(href), wml_text(text)),
        Item::Form(f) => render_form(f),
    }
}

fn deck(title: &str, body: &str, nav: &str) -> String {
    let nav = if nav.is_empty() { String::new() } else { format!("</p><p>{nav}") };
    format!("<wml><card title=\"{}\"><p>{body}{nav}</p></card></wml>", wml_attr(title))
}

fn nav_line(index: usize, count: usize, href: &dyn Fn(usize) -> String) -> String {
    if count <= 1 {
        return String::new();
    }
    let mut parts = Vec::new();
    if index > 0 {
        parts.push(format!("<a href=\"{}\">Prev</a>", wml_attr(&href(index - 1))));
    }
    parts.push(format!("{}/{}", index + 1, count));
    if index + 1 < count {
        parts.push(format!("<a href=\"{}\">Next</a>", wml_attr(&href(index + 1))));
    }
    parts.join(" ")
}

/// Split escaped text into chunks of at most `max` bytes, at spaces where possible and never
/// inside an entity or a `$$` pair.
fn split_escaped(text: &str, max: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while rest.len() > max {
        let mut cut = max;
        while cut > 0 && !rest.is_char_boundary(cut) {
            cut -= 1;
        }
        if let Some(sp) = rest[..cut].rfind(' ').filter(|&p| p > max / 2) {
            cut = sp;
        } else {
            // Back off out of a partial entity or `$$` pair.
            if let Some(amp) = rest[..cut].rfind('&') {
                if !rest[amp..cut].contains(';') {
                    cut = amp;
                }
            }
            let dollars = rest[..cut].bytes().rev().take_while(|&b| b == b'$').count();
            if dollars % 2 == 1 {
                cut -= 1;
            }
        }
        if cut == 0 {
            break;
        }
        out.push(rest[..cut].trim_end().to_string());
        rest = rest[cut..].trim_start();
    }
    if !rest.is_empty() {
        out.push(rest.to_string());
    }
    out
}

/// Pack a document into WML decks of at most `budget` bytes each. `page_href(n)` is the URL of
/// page `n` (0-based), used for the Prev/Next links.
pub fn paginate(doc: &Document, budget: usize, page_href: &dyn Fn(usize) -> String) -> Vec<String> {
    // Reserve room for the frame and the widest navigation line any page can carry.
    let frame = deck(&doc.title, "", "x").len() - 1;
    let worst_nav = nav_line(1, MAX_PAGES + 1, page_href).len().max(nav_line(MAX_PAGES - 1, MAX_PAGES + 1, page_href).len());
    let avail = budget.saturating_sub(frame + worst_nav).max(40);

    let mut fragments: Vec<String> = Vec::new();
    for item in &doc.items {
        let r = render_item(item);
        if r.len() <= avail {
            fragments.push(r);
        } else if let Item::Text(_) = item {
            fragments.extend(split_escaped(&r, avail));
        } else if let Item::Link { text, .. } = item {
            fragments.push(wml_text(text));
        }
    }

    let mut bodies: Vec<String> = Vec::new();
    let mut cur = String::new();
    for f in fragments {
        let is_break = f == "<br/>";
        if cur.len() + f.len() + 1 > avail && !cur.is_empty() {
            bodies.push(std::mem::take(&mut cur));
        }
        if is_break && (cur.is_empty() || cur.ends_with("<br/>")) {
            continue;
        }
        if !cur.is_empty() && !is_break && !cur.ends_with("<br/>") {
            cur.push(' ');
        }
        cur.push_str(&f);
    }
    if !cur.is_empty() {
        bodies.push(cur);
    }
    for body in &mut bodies {
        while body.ends_with("<br/>") {
            body.truncate(body.len() - 5);
        }
    }
    if bodies.is_empty() {
        bodies.push("(empty page)".to_string());
    }
    if bodies.len() > MAX_PAGES {
        bodies.truncate(MAX_PAGES);
        bodies[MAX_PAGES - 1] = "(rest of page cut)".to_string();
    }

    let count = bodies.len();
    bodies
        .iter()
        .enumerate()
        .map(|(n, body)| deck(&doc.title, body, &nav_line(n, count, page_href)))
        .collect()
}

/// A one-card message page, e.g. for a refused or failed fetch.
pub fn message_page(title: &str, lines: &[&str], budget: usize) -> String {
    let body = lines.iter().map(|l| wml_text(&truncate_chars(l, 120))).collect::<Vec<_>>().join("<br/>");
    let page = deck(title, &body, "");
    if page.len() <= budget {
        page
    } else {
        deck(title, &wml_text(&truncate_chars(lines.first().copied().unwrap_or(""), 60)), "")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Url {
        Url::parse("https://lite.duckduckgo.com/lite/").unwrap()
    }

    fn href(n: usize) -> String {
        format!("http://10.0.0.1/p/7/{n}")
    }

    #[test]
    fn keeps_text_links_and_title_and_drops_scripts() {
        let html = "<html><head><title>My &amp; Page</title><style>p{}</style><script>var a='<b>';</script></head>\
                    <body><h1>Hello</h1><p>One&nbsp;two <a href=\"/x?a=1&amp;b=2\">Go <img src=i.png alt=pic></a></p>\
                    <select name=kl><option>Argentina</option></select><ul><li>A</li><li>B</li></ul></body></html>";
        let doc = parse_html(html, &base());
        assert_eq!(doc.title, "My & Page");
        assert_eq!(
            doc.items,
            vec![
                Item::Text("Hello".into()),
                Item::Break,
                Item::Text("One two".into()),
                Item::Link { href: "https://lite.duckduckgo.com/x?a=1&b=2".into(), text: "Go".into() },
                Item::Break,
                Item::Text("* A".into()),
                Item::Break,
                Item::Text("* B".into()),
            ]
        );
    }

    #[test]
    fn unwraps_duckduckgo_result_links() {
        let u = resolve_link(&base(), "//duckduckgo.com/l/?uddg=https%3A%2F%2Fen.wikipedia.org%2Fwiki%2FTETRA&rut=abc").unwrap();
        assert_eq!(u.as_str(), "https://en.wikipedia.org/wiki/TETRA");
        assert!(resolve_link(&base(), "javascript:alert(1)").is_none());
        assert!(resolve_link(&base(), "#top").is_none());
        assert_eq!(resolve_link(&base(), "/a#frag").unwrap().as_str(), "https://lite.duckduckgo.com/a");
    }

    #[test]
    fn post_search_form_becomes_a_get_form() {
        let html = "<form action=\"/lite/\" method=\"post\"><input class='query' type=\"text\" name=\"q\" value=\"a&quot;b\" />\
                    <input type=hidden name=kl value=us-en><input type=\"submit\" value=\"Search\" /></form>";
        let doc = parse_html(html, &base());
        let Item::Form(f) = &doc.items[0] else { panic!("form expected: {:?}", doc.items) };
        assert_eq!(f.action, "https://lite.duckduckgo.com/lite/");
        assert_eq!(f.submit, "Search");
        let wml = render_item(&doc.items[0]);
        assert_eq!(
            wml,
            "<input name=\"v0\" value=\"a&quot;b\"/><anchor>Search<go href=\"https://lite.duckduckgo.com/lite/\" method=\"get\">\
             <postfield name=\"q\" value=\"$(v0)\"/><postfield name=\"kl\" value=\"us-en\"/></go></anchor>"
        );
    }

    #[test]
    fn dollar_signs_are_not_wml_variables() {
        assert_eq!(wml_text("costs $5 & <more>"), "costs $$5 &amp; &lt;more&gt;");
    }

    #[test]
    fn every_page_fits_the_budget_and_links_to_its_neighbours() {
        let mut items = Vec::new();
        for n in 0..30 {
            items.push(Item::Link { href: format!("https://example.com/article/{n}"), text: format!("Result number {n}") });
            items.push(Item::Text("Some snippet text describing the result in a few words. ".repeat(3)));
            items.push(Item::Break);
        }
        let doc = Document { title: "Results".into(), items };
        let pages = paginate(&doc, 480, &href);
        assert!(pages.len() > 3);
        for (n, p) in pages.iter().enumerate() {
            assert!(p.len() <= 480, "page {n} is {} bytes", p.len());
            assert!(p.starts_with("<wml><card title=\"Results\"><p>") && p.ends_with("</p></card></wml>"));
            let links_to = |m: usize| p.contains(&format!("\"{}\"", href(m)));
            assert_eq!(links_to(n + 1), n + 1 < pages.len(), "next link on page {n}");
            assert_eq!(n > 0 && links_to(n - 1), n > 0, "prev link on page {n}");
        }
    }

    #[test]
    fn long_text_is_split_without_breaking_entities() {
        let doc = Document { title: "T".into(), items: vec![Item::Text("a&b $ ".repeat(200))] };
        for p in paginate(&doc, 200, &href) {
            assert!(p.len() <= 200);
            let body = &p[p.find("<p>").unwrap() + 3..];
            let whole = |s: &str| ["amp;", "lt;", "gt;", "quot;", "apos;"].iter().any(|e| s.starts_with(e));
            assert!(body.split('&').skip(1).all(whole), "split inside an entity: {body}");
            assert!(body.split("$$").all(|s| !s.contains('$')), "split inside a $$ pair: {body}");
        }
    }

    #[test]
    fn single_page_has_no_navigation() {
        let doc = Document { title: "T".into(), items: vec![Item::Text("hi".into())] };
        assert_eq!(paginate(&doc, 480, &href), vec!["<wml><card title=\"T\"><p>hi</p></card></wml>".to_string()]);
    }

    #[test]
    fn duckduckgo_lite_results_page_converts() {
        let html = r#"<html><head><title>tetra at DuckDuckGo</title></head><body>
            <form action="/lite/" method="post"><input class='query' type="text" size="40" name="q" value="tetra" />
            <select class="submit" name="kl"><option value="">All Regions</option><option value="ar-es">Argentina</option></select>
            <input class='submit' type="submit" value="Search" /></form>
            <table><tr><td valign="top">1.&nbsp;</td><td><a rel="nofollow" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fen.wikipedia.org%2Fwiki%2FTETRA&amp;rut=1" class='result-link'>TETRA - Wikipedia</a></td></tr>
            <tr><td class='result-snippet'>Terrestrial Trunked Radio (<b>TETRA</b>) is a standard.</td></tr>
            <tr><td><span class='link-text'>en.wikipedia.org/wiki/TETRA</span></td></tr></table>
            <form action="/lite/" method="post"><input type="submit" class='navbutton' value="Next Page &gt;" />
            <input type="hidden" name="q" value="tetra" /><input type="hidden" name="s" value="10" /></form></body></html>"#;
        let doc = parse_html(html, &base());
        assert!(!format!("{:?}", doc.items).contains("Argentina"), "region dropdown dropped");
        assert!(doc.items.contains(&Item::Link { href: "https://en.wikipedia.org/wiki/TETRA".into(), text: "TETRA - Wikipedia".into() }));
        let pages = paginate(&doc, 480, &href);
        let all = pages.join("");
        assert!(all.contains("Terrestrial Trunked Radio (TETRA) is a standard."));
        assert!(all.contains("<anchor>Next Page &gt;<go href=\"https://lite.duckduckgo.com/lite/\" method=\"get\"><postfield name=\"q\" value=\"tetra\"/><postfield name=\"s\" value=\"10\"/></go></anchor>"));
        assert!(pages.iter().all(|p| p.len() <= 480));
    }

    #[test]
    fn message_page_fits() {
        let p = message_page("Not allowed", &["en.wikipedia.org is not on the allowlist"], 480);
        assert_eq!(p, "<wml><card title=\"Not allowed\"><p>en.wikipedia.org is not on the allowlist</p></card></wml>");
    }
}
