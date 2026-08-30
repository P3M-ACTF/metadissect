use crate::net::is_tty_stdio;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Product {
    Metadissect,
    Metainstructor,
    Metatrace,
    Metafake,
}

impl Product {
    pub fn ascii(&self) -> &'static str {
        match self {
            Product::Metadissect => METADISSECT,
            Product::Metainstructor => METAINSTRUCTOR,
            Product::Metatrace => METATRACE,
            Product::Metafake => METAFAKE,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Product::Metadissect => "MetaDissect",
            Product::Metainstructor => "MetaInstructor",
            Product::Metatrace => "MetaTrace",
            Product::Metafake => "MetaFake",
        }
    }
}

pub fn should_show_banner(no_banner: bool) -> bool {
    if no_banner {
        return false;
    }
    if std::env::var("CI").is_ok() || std::env::var("NO_COLOR").is_ok() {
        return false;
    }
    is_tty_stdio()
}

pub fn maybe_print_banner(product: Product, no_banner: bool) {
    if should_show_banner(no_banner) {
        println!("{}", product.ascii());
        println!("  {}", product.label());
        println!();
    }
}

const METADISSECT: &str = r"
  ╔══════════════════════════════════════╗
  ║  MetaDissect · metadata extraction ║
  ╚══════════════════════════════════════╝";

const METAINSTRUCTOR: &str = r"
  ╔══════════════════════════════════════╗
  ║ MetaInstructor · educational viewer  ║
  ╚══════════════════════════════════════╝";

const METATRACE: &str = r"
  ╔══════════════════════════════════════╗
  ║  MetaTrace · forensic metadata lab   ║
  ╚══════════════════════════════════════╝";

const METAFAKE: &str = r"
  ╔══════════════════════════════════════╗
  ║  MetaFake · mutate metadata copies   ║
  ╚══════════════════════════════════════╝";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banner_lines_non_empty() {
        for p in [
            Product::Metadissect,
            Product::Metainstructor,
            Product::Metatrace,
            Product::Metafake,
        ] {
            assert!(p.ascii().contains(p.label()));
        }
    }
}
