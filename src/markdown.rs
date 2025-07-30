use anyhow::{Context, Result};
use colored::*;
use pulldown_cmark::{Parser, Event, Tag, CodeBlockKind, HeadingLevel};
use regex::Regex;

#[cfg(feature = "images")]
use viuer::{Config as ViuerConfig, print_from_file};

/// Markdown renderer for terminal output with image support
pub struct MarkdownRenderer {
    /// Whether to enable image display
    enable_images: bool,
}

impl MarkdownRenderer {
    pub fn new(enable_images: bool) -> Self {
        Self {
            enable_images,
        }
    }

    /// Render markdown text to colored terminal output
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
                        Tag::Paragraph => {
                            if !output.is_empty() && !output.ends_with('\n') {
                                output.push('\n');
                            }
                        }
                        Tag::List(start_number) => {
                            list_stack.push(start_number.is_some());
                            output.push('\n');
                        }
                        Tag::Item => {
                            let indent = "  ".repeat(list_stack.len().saturating_sub(1));
                            if let Some(&is_ordered) = list_stack.last() {
                                if is_ordered {
                                    output.push_str(&format!("{}1. ", indent));
                                } else {
                                    output.push_str(&format!("{}• ", indent));
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
                                if !lang.is_empty() {
                                    output.push_str(&format!("```{}\n", lang.bright_black()));
                                } else {
                                    output.push_str("```\n");
                                }
                            } else {
                                output.push_str("```\n");
                            }
                        }
                        // Inline code is handled in Event::Code, not as a Tag
                        Tag::Link(_link_type, dest_url, title) => {
                            // Handle hyperlinks
                            if !title.is_empty() {
                                output.push_str(&format!("{} ({})", title.bright_blue().underline(), dest_url.bright_black()));
                            } else {
                                output.push_str(&dest_url.bright_blue().underline().to_string());
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
                        Tag::Paragraph => {
                            output.push('\n');
                        }
                        Tag::List(_) => {
                            list_stack.pop();
                            output.push('\n');
                        }
                        Tag::Item => {
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
                        Tag::BlockQuote => {
                            output.push('\n');
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
                    output.push_str(&self.strip_html(&html));
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
            if !title.is_empty() {
                output.push_str(&format!("[Image: {}] ({})\n", title.bright_green(), url.bright_black()));
            } else {
                output.push_str(&format!("[Image] ({})\n", url.bright_black()));
            }
            return Ok(());
        }

        #[cfg(feature = "images")]
        {
            if url.starts_with("data:image/") {
                // Handle embedded base64 images
                self.handle_embedded_image(output, url, title)?;
            } else if url.starts_with("http://") || url.starts_with("https://") {
                // Handle remote images
                self.handle_remote_image(output, url, title)?;
            } else {
                // Handle local file paths
                self.handle_local_image(output, url, title)?;
            }
        }

        #[cfg(not(feature = "images"))]
        {
            // Feature disabled, show as link
            if !title.is_empty() {
                output.push_str(&format!("[Image: {}] ({})\n", title.bright_green(), url.bright_black()));
            } else {
                output.push_str(&format!("[Image] ({})\n", url.bright_black()));
            }
        }

        Ok(())
    }

    #[cfg(feature = "images")]
    fn handle_embedded_image(&mut self, output: &mut String, data_url: &str, title: &str) -> Result<()> {
        use base64::Engine;
        
        // Parse data URL: data:image/png;base64,iVBORw0KGgoAAAANS...
        let re = Regex::new(r"data:image/([^;]+);base64,(.+)").unwrap();
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
                        output.push_str(&format!("\n{}\n", title.bright_green()));
                    }
                }
                Err(_) => {
                    output.push_str(&format!("[Image display failed: {}]\n", 
                        if !title.is_empty() { title } else { "embedded image" }));
                }
            }
            
            // Clean up
            let _ = std::fs::remove_file(&temp_path);
        } else {
            output.push_str(&format!("[Invalid data URL: {}]\n", 
                if !title.is_empty() { title } else { "embedded image" }));
        }
        
        Ok(())
    }

    #[cfg(feature = "images")]
    fn handle_remote_image(&mut self, output: &mut String, url: &str, title: &str) -> Result<()> {
        // For now, just show as link - could implement downloading in the future
        if !title.is_empty() {
            output.push_str(&format!("[Remote Image: {}] ({})\n", title.bright_green(), url.bright_black()));
        } else {
            output.push_str(&format!("[Remote Image] ({})\n", url.bright_black()));
        }
        Ok(())
    }

    #[cfg(feature = "images")]
    fn handle_local_image(&mut self, output: &mut String, path: &str, title: &str) -> Result<()> {
        let config = ViuerConfig {
            width: Some(80),
            height: Some(24),
            ..Default::default()
        };
        
        match print_from_file(path, &config) {
            Ok(_) => {
                if !title.is_empty() {
                    output.push_str(&format!("\n{}\n", title.bright_green()));
                }
            }
            Err(_) => {
                output.push_str(&format!("[Image not found: {}]\n", 
                    if !title.is_empty() { title } else { path }));
            }
        }
        
        Ok(())
    }

    /// Strip HTML tags from text
    fn strip_html(&self, html: &str) -> String {
        let re = Regex::new(r"<[^>]*>").unwrap();
        re.replace_all(html, "").to_string()
    }

    /// Check if text contains markdown syntax
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
            let re = Regex::new(pattern).unwrap();
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
    fn test_basic_rendering() {
        let mut renderer = MarkdownRenderer::new(false);
        let result = renderer.render("# Header\n\nThis is **bold** and *italic*.").unwrap();
        // Just test that it doesn't crash - detailed output testing would be complex
        assert!(!result.is_empty());
    }

    #[test]
    fn test_code_rendering() {
        let mut renderer = MarkdownRenderer::new(false);
        let result = renderer.render("Inline `code` and\n\n```rust\nfn main() {}\n```").unwrap();
        assert!(!result.is_empty());
    }

    #[test]
    fn test_list_rendering() {
        let mut renderer = MarkdownRenderer::new(false);
        let result = renderer.render("- Item 1\n- Item 2\n\n1. Numbered\n2. List").unwrap();
        assert!(!result.is_empty());
    }
}