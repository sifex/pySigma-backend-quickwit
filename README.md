<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://quickwit.io/img/quickwit-dark-logo.png">
  <img width="300" alt="Sigma Logo" src="https://quickwit.io/img/quickwit-light-logo.png">
</picture>

# pySigma Quickwit Backend


![Tests](https://github.com/sifex/pySigma-backend-quickwit/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/sifex/069da779c05d9acd68207eb3979e037a/raw/sifex-pySigma-backend-quickwit.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

This is the Quickwit backend for pySigma. It provides the package `sigma.backends.quickwit` with the `QuickwitBackend` class.

## Installation

```bash
# Install the plugin
sigma plugin install pySigma-backend-quickwit
```

## Usage

```bash
sigma convert -t quickwit ./rule.yml
```

For more information about Sigma and [how to convert Sigma rules, visit the documentation here →](https://sigmahq.io/docs/guide/getting-started.html)

## Maintainers

This backend is currently maintained by:

* [Alex Sinnott](https://github.com/sifex/)