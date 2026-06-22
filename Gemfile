# Gemfile — only needed for local preview with `bundle exec jekyll serve`.
# GitHub Pages itself uses its own pinned gem set; the remote_theme plugin
# pulls just-the-docs at build time.

source "https://rubygems.org"

# Match the GitHub Pages gem so local preview matches production rendering.
gem "github-pages", group: :jekyll_plugins

group :jekyll_plugins do
  gem "jekyll-remote-theme"
  gem "jekyll-seo-tag"
  gem "jekyll-sitemap"
end

# Windows + JRuby don't include zoneinfo files by default.
platforms :mingw, :x64_mingw, :mswin, :jruby do
  gem "tzinfo", ">= 1", "< 3"
  gem "tzinfo-data"
end

# webrick was removed from the Ruby 3+ standard library.
gem "webrick", "~> 1.8"
