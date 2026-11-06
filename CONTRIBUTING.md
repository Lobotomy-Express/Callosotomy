# Contributing

Thanks for helping. A few ground rules, because this is security software:

- **Security issues go through [SECURITY.md](SECURITY.md)**, not public issues or pull requests.
- **Don't add third-party dependencies.** Every package is an attack surface. If you think you need one, open an issue to discuss it first.
- **Keep the service small.** Logic that can be pure goes in `Callosotomy.Core` with unit tests.
- **Fail closed.** No change may make a crash, a timeout or an error lift a block.
- **Warnings are errors.** Run `dotnet build` and `dotnet test` before opening a pull request.

By contributing, you agree your work is licensed under GPL-3.0.
