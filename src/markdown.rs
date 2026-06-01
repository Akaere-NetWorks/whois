//! Markdown rendering for terminal output with optional image support.
//!
//! Uses [`pulldown_cmark`] to parse Markdown and produces colored terminal
//! output via [`colored`]. Supports headings, emphasis, bold, inline code,
//! code blocks, lists, blockquotes, links, images, rules, and HTML stripping.
//!
//! When the `images` feature is enabled, inline images (base64, local files)
//! are rendered using `viuer`; otherwise they are shown as text links.

use std::fmt::Write as FmtWrite;
use std::sync::LazyLock;

use anyhow::{Context, Result};
use colored::Colorize;
use pulldown_cmark::{Parser, Event, Tag, CodeBlockKind, HeadingLevel};
use regex::Regex;

static DATA_IMAGE_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"data:image/([^;]+);base64,(.+)").expect("invalid data image regex pattern")
});

static HTML_TAG_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"<[^>]*>").expect("invalid HTML tag regex pattern")
});

#[cfg(feature = "images")]
use viuer::{Config as ViuerConfig, print_from_file};

/// Markdown renderer for terminal output with optional image support.
pub struct MarkdownRenderer {
    /// Whether to enable image display.
    enable_images: bool,
}

impl MarkdownRenderer {
    /// Create a new `MarkdownRenderer`.
    ///
    /// When `enable_images` is `true` and the `images` feature is active,
    /// embedded and local images will be rendered inline in the terminal.
    #[must_use] 
    pub fn new(enable_images: bool) -> Self {
        Self {
            enable_images,
        }
    }

    /// Render Markdown text to colored terminal output.
    ///
    /// # Errors
    ///
    /// Returns an error if image processing (base64 decoding, file I/O, or
    /// terminal rendering) fails. Plain Markdown rendering without images
    /// is infallible.
    #[expect(clippy::too_many_lines, reason = "large event-driven render loop, splitting would obscure logic")]
    pub fn render(&mut self, markdown: &str) -> Result<String> {
        let parser = Parser::new(markdown);
        let mut output = String::new();
        let mut in_code_block = false;
        let mut in_emphasis = false;
        let mut in_strong = false;
        let mut in_heading = false;
        let mut heading_level = HeadingLevel::H1;
        let mut list_stack: Vec<bool> = Vec::new(); // true for ordered, false for unordered

        for event in parser {
            match event {
                Event::Start(tag) => {
                    match tag {
                        Tag::Heading(level, _, _) => {
                            in_heading = true;
                            heading_level = level;
                            output.push('\n');
                        }
                        Tag::Paragraph
                            if !output.is_empty() && !output.ends_with('\n') =>
                        {
                            output.push('\n');
                        }
                        Tag::List(start_number) => {
                            list_stack.push(start_number.is_some());
                            output.push('\n');
                        }
                        Tag::Item => {
                            let indent = "  ".repeat(list_stack.len().saturating_sub(1));
                            if let Some(&is_ordered) = list_stack.last() {
                                if is_ordered {
                                    let _ = write!(output, "{indent}1. ");
                                } else {
                                    let _ = write!(output, "{indent}• ");
                                }
                            }
                        }
                        Tag::Emphasis => {
                            in_emphasis = true;
                        }
                        Tag::Strong => {
                            in_strong = true;
                        }
                        Tag::CodeBlock(kind) => {
                            in_code_block = true;
                            output.push('\n');
                            if let CodeBlockKind::Fenced(lang) = kind {
                                if lang.is_empty() {
                                    output.push_str("```\n");
                                } else {
                                    let _ = writeln!(output, "```{}", lang.bright_black());
                                }
                            } else {
                                output.push_str("```\n");
                            }
                        }
                        // Inline code is handled in Event::Code, not as a Tag
                        Tag::Link(_link_type, dest_url, title) => {
                            // Handle hyperlinks
                            if title.is_empty() {
                                output.push_str(&dest_url.bright_blue().underline().to_string());
                            } else {
                                let _ = write!(output, "{} ({})", title.bright_blue().underline(), dest_url.bright_black());
                            }
                        }
                        Tag::Image(_link_type, dest_url, title) => {
                            self.handle_image(&mut output, dest_url.as_ref(), title.as_ref())?;
                        }
                        Tag::BlockQuote => {
                            output.push_str(&"▍ ".bright_black().to_string());
                        }
                        _ => {}
                    }
                }
                Event::End(tag) => {
                    match tag {
                        Tag::Heading(_, _, _) => {
                            in_heading = false;
                            output.push('\n');
                        }
                        Tag::Paragraph | Tag::Item | Tag::BlockQuote => {
                            output.push('\n');
                        }
                        Tag::List(_) => {
                            list_stack.pop();
                            output.push('\n');
                        }
                        Tag::Emphasis => {
                            in_emphasis = false;
                        }
                        Tag::Strong => {
                            in_strong = false;
                        }
                        Tag::CodeBlock(_) => {
                            in_code_block = false;
                            output.push_str("```\n\n");
                        }
                        _ => {}
                    }
                }
                Event::Text(text) => {
                    let rendered_text = if in_code_block {
                        // Code block - use monospace styling
                        text.bright_white().on_black().to_string()
                    } else if in_heading {
                        // Heading - use appropriate colors based on level
                        match heading_level {
                            HeadingLevel::H1 => text.bright_white().bold().to_string(),
                            HeadingLevel::H2 => text.bright_cyan().bold().to_string(),
                            HeadingLevel::H3 => text.bright_green().bold().to_string(),
                            HeadingLevel::H4 => text.bright_yellow().bold().to_string(),
                            HeadingLevel::H5 => text.bright_magenta().bold().to_string(),
                            HeadingLevel::H6 => text.bright_blue().bold().to_string(),
                        }
                    } else if in_strong {
                        text.bold().to_string()
                    } else if in_emphasis {
                        text.italic().to_string()
                    } else {
                        text.to_string()
                    };
                    output.push_str(&rendered_text);
                }
                Event::Code(code) => {
                    // Inline code
                    output.push_str(&code.bright_white().on_black().to_string());
                }
                Event::Html(html) => {
                    // Handle HTML tags if needed - for now, just strip them
                    output.push_str(&Self::strip_html(&html));
                }
                Event::SoftBreak => {
                    output.push(' ');
                }
                Event::HardBreak => {
                    output.push('\n');
                }
                Event::Rule => {
                    output.push_str(&"─".repeat(80).bright_black().to_string());
                    output.push('\n');
                }
                _ => {}
            }
        }

        Ok(output)
    }

    /// Handle image display in terminal
    fn handle_image(&mut self, output: &mut String, url: &str, title: &str) -> Result<()> {
        if !self.enable_images {
            // Images disabled, show as link
            if title.is_empty() {
                let _ = writeln!(output, "[Image] ({})", url.bright_black());
            } else {
                let _ = writeln!(output, "[Image: {}] ({})", title.bright_green(), url.bright_black());
            }
            return Ok(());
        }

        #[cfg(feature = "images")]
        {
            if url.starts_with("data:image/") {
                // Handle embedded base64 images
                Self::handle_embedded_image(output, url, title)?;
            } else if url.starts_with("http://") || url.starts_with("https://") {
                // Handle remote images
                Self::handle_remote_image(output, url, title);
            } else {
                // Handle local file paths
                Self::handle_local_image(output, url, title);
            }
        }

        #[cfg(not(feature = "images"))]
        {
            // Feature disabled, show as link
            if !title.is_empty() {
                let _ = writeln!(output, "[Image: {}] ({})", title.bright_green(), url.bright_black());
            } else {
                let _ = writeln!(output, "[Image] ({})", url.bright_black());
            }
        }

        Ok(())
    }

    #[cfg(feature = "images")]
    fn handle_embedded_image(output: &mut String, data_url: &str, title: &str) -> Result<()> {
        use base64::Engine;
        
        // Parse data URL: data:image/png;base64,iVBORw0KGgoAAAANS...
        let re = &*DATA_IMAGE_REGEX;
        if let Some(captures) = re.captures(data_url) {
            let format = &captures[1];
            let base64_data = &captures[2];
            
            // Decode base64
            let image_data = base64::engine::general_purpose::STANDARD
                .decode(base64_data)
                .context("Failed to decode base64 image data")?;
            
            // Write to temporary file
            let temp_path = format!("/tmp/whois_image_{}.{}", 
                std::process::id(), format);
            std::fs::write(&temp_path, &image_data)
                .context("Failed to write temporary image file")?;
            
            // Display image
            let config = ViuerConfig {
                width: Some(80),
                height: Some(24),
                ..Default::default()
            };
            
            match print_from_file(&temp_path, &config) {
                Ok(_) => {
                    if !title.is_empty() {
                        let _ = write!(output, "\n{}\n", title.bright_green());
                    }
                }
                Err(_) => {
                    let _ = writeln!(output, "[Image display failed: {}]", 
                        if title.is_empty() { "embedded image" } else { title });
                }
            }
            
            // Clean up
            let _ = std::fs::remove_file(&temp_path);
        } else {
            let _ = writeln!(output, "[Invalid data URL: {}]", 
                if title.is_empty() { "embedded image" } else { title });
        }
        
        Ok(())
    }

    #[cfg(feature = "images")]
    fn handle_remote_image(output: &mut String, url: &str, title: &str) {
        // For now, just show as link - could implement downloading in the future
        if title.is_empty() {
            let _ = writeln!(output, "[Remote Image] ({})", url.bright_black());
        } else {
            let _ = writeln!(output, "[Remote Image: {}] ({})", title.bright_green(), url.bright_black());
        }
    }

    #[cfg(feature = "images")]
    fn handle_local_image(output: &mut String, path: &str, title: &str) {
        let config = ViuerConfig {
            width: Some(80),
            height: Some(24),
            ..Default::default()
        };
        
        match print_from_file(path, &config) {
            Ok(_) => {
                if !title.is_empty() {
                    let _ = write!(output, "\n{}\n", title.bright_green());
                }
            }
            Err(_) => {
                let _ = writeln!(output, "[Image not found: {}]", 
                    if title.is_empty() { path } else { title });
            }
        }
    }

    /// Strip HTML tags from text
    fn strip_html(html: &str) -> String {
        let re = &*HTML_TAG_REGEX;
        re.replace_all(html, "").to_string()
    }

    /// Check if text contains markdown syntax
    ///
    /// # Panics
    ///
    /// Panics if any of the hardcoded regex patterns are invalid. Since all
    /// patterns are defined at compile time, this will never happen in practice.
    #[must_use] 
    pub fn is_markdown(text: &str) -> bool {
        // Simple heuristics to detect markdown
        let markdown_patterns = [
            r"^#{1,6}\s",          // Headers
            r"\*\*.*\*\*",         // Bold
            r"\*.*\*",             // Italic
            r"`.*`",               // Inline code
            r"```",                // Code blocks
            r"^\s*[-*+]\s",        // Unordered lists
            r"^\s*\d+\.\s",        // Ordered lists
            r"\[.*\]\(.*\)",       // Links
            r"!\[.*\]\(.*\)",      // Images
            r"^\s*>",              // Blockquotes
        ];
        
        for pattern in &markdown_patterns {
            let re = Regex::new(pattern).expect("hardcoded markdown pattern should be valid");
            if re.is_match(text) {
                return true;
            }
        }
        
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_markdown() {
        assert!(MarkdownRenderer::is_markdown("# Header"));
        assert!(MarkdownRenderer::is_markdown("**bold text**"));
        assert!(MarkdownRenderer::is_markdown("- list item"));
        assert!(MarkdownRenderer::is_markdown("[link](http://example.com)"));
        assert!(MarkdownRenderer::is_markdown("![image](image.png)"));
        assert!(MarkdownRenderer::is_markdown("> blockquote"));
        assert!(MarkdownRenderer::is_markdown("```code```"));
        assert!(!MarkdownRenderer::is_markdown("plain text"));
    }

    #[test]
    fn test_basic_rendering() -> Result<()> {
        let mut renderer = MarkdownRenderer::new(false);
        let result = renderer.render("# Header\n\nThis is **bold** and *italic*.")?;
        // Just test that it doesn't crash - detailed output testing would be complex
        assert!(!result.is_empty());
        Ok(())
    }

    #[test]
    fn test_code_rendering() -> Result<()> {
        let mut renderer = MarkdownRenderer::new(false);
        let result = renderer.render("Inline `code` and\n\n```rust\nfn main() {}\n```")?;
        assert!(!result.is_empty());
        Ok(())
    }

    #[test]
    fn test_list_rendering() -> Result<()> {
        let mut renderer = MarkdownRenderer::new(false);
        let result = renderer.render("- Item 1\n- Item 2\n\n1. Numbered\n2. List")?;
        assert!(!result.is_empty());
        Ok(())
    }
}