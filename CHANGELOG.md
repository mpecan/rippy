# Changelog

## [0.2.0](https://github.com/mpecan/rippy/compare/rippy-cli-v0.1.3...rippy-cli-v0.2.0) (2026-04-15)


### ⚠ BREAKING CHANGES

* reject unknown fields in TOML rule entries ([#120](https://github.com/mpecan/rippy/issues/120))

### Bug Fixes

* reject unknown fields in TOML rule entries ([#120](https://github.com/mpecan/rippy/issues/120)) ([3aaa91f](https://github.com/mpecan/rippy/commit/3aaa91f41184b499e1416ffab748f206cf1f134c))


### Documentation

* document conditional `when` clauses ([#124](https://github.com/mpecan/rippy/issues/124)) ([f4d7021](https://github.com/mpecan/rippy/commit/f4d7021efa1087fcc765050b09f4dd97c62ac2f9))


### Code Refactoring

* source built-in package metadata from TOML ([#122](https://github.com/mpecan/rippy/issues/122)) ([e2ae1b0](https://github.com/mpecan/rippy/commit/e2ae1b04f08bf989204bf981ecaf03949dad1050))

## [0.1.3](https://github.com/mpecan/rippy/compare/rippy-cli-v0.1.2...rippy-cli-v0.1.3) (2026-04-13)


### Features

* support user-defined custom packages ([#116](https://github.com/mpecan/rippy/issues/116)) ([8ab2578](https://github.com/mpecan/rippy/commit/8ab257858c80a1fa6f75162c47611f7141eb2654))


### Documentation

* prefer .rippy.toml over the legacy flat config format ([#114](https://github.com/mpecan/rippy/issues/114)) ([7c6a0ee](https://github.com/mpecan/rippy/commit/7c6a0ee6535521b58ac2f08c99ffd855d2e0020b))

## [0.1.2](https://github.com/mpecan/rippy/compare/rippy-cli-v0.1.1...rippy-cli-v0.1.2) (2026-04-13)


### Bug Fixes

* **ci:** add aarch64-unknown-linux-gnu to pinned toolchain targets ([#113](https://github.com/mpecan/rippy/issues/113)) ([7f9b59d](https://github.com/mpecan/rippy/commit/7f9b59d00eedf1dbad79ff105f6804b466487201))
* **site:** bump Node to 22 for Astro 6 compatibility ([#112](https://github.com/mpecan/rippy/issues/112)) ([3c62502](https://github.com/mpecan/rippy/commit/3c62502849a576708abda959df827418cda13b3c))

## [0.1.1](https://github.com/mpecan/rippy/compare/rippy-cli-v0.1.0...rippy-cli-v0.1.1) (2026-04-13)


### Features

* add --dry-run awareness to helm handler ([#19](https://github.com/mpecan/rippy/issues/19)) ([0a64d42](https://github.com/mpecan/rippy/commit/0a64d428fd750360320744a72a38ab5d135c2a31))
* add --dry-run awareness to helm handler ([#29](https://github.com/mpecan/rippy/issues/29)) ([382b5de](https://github.com/mpecan/rippy/commit/382b5debd07d0fbf8415fb78b9c7caf37298ebb1))
* add `rippy allow` / `rippy deny` / `rippy ask` commands ([#59](https://github.com/mpecan/rippy/issues/59)) ([baad51f](https://github.com/mpecan/rippy/commit/baad51f9137e9895d6b84535b5b0bfc421c52f5a))
* add `rippy inspect` command for rule listing and decision tracing ([#51](https://github.com/mpecan/rippy/issues/51)) ([7d4d8c9](https://github.com/mpecan/rippy/commit/7d4d8c9d53a0fa2ebaeb0d8be6df1f7c9375f935))
* add `rippy setup tokf` command ([#40](https://github.com/mpecan/rippy/issues/40)) ([5359a70](https://github.com/mpecan/rippy/commit/5359a70ee5f69a27190b05b1f2851cbf999cfb7b))
* add `rippy setup tokf` command for automatic tokf integration ([db4a56f](https://github.com/mpecan/rippy/commit/db4a56f197f16660e6cc608ef196dd9d36baaed3))
* add ansible handler for safe-mode detection ([#23](https://github.com/mpecan/rippy/issues/23)) ([911abef](https://github.com/mpecan/rippy/commit/911abeff87a40fa825511704b4ce8cdcbefd2386))
* add ansible handler for safe-mode detection ([#33](https://github.com/mpecan/rippy/issues/33)) ([a45c5f6](https://github.com/mpecan/rippy/commit/a45c5f6e0072235320f2943b76b117b8737a18dc))
* add cd/pushd/popd handler with path-aware scope checking ([6b4b3fe](https://github.com/mpecan/rippy/commit/6b4b3fe764bc1b25155a61ef69733974af01e27c))
* add cd/pushd/popd handler with path-aware scope checking ([#67](https://github.com/mpecan/rippy/issues/67)) ([d93738b](https://github.com/mpecan/rippy/commit/d93738b594f4041b44c4fd12050e5ad0e62b2c11))
* add compound command safety analysis ([7c151bd](https://github.com/mpecan/rippy/commit/7c151bd98607593707f138a99224290ebb8628cf))
* add compound command safety analysis ([#53](https://github.com/mpecan/rippy/issues/53)) ([00e3d11](https://github.com/mpecan/rippy/commit/00e3d113f810d1b6107ef4d775c169668b2e4f7e))
* add condition module with when clause parsing and evaluation ([#46](https://github.com/mpecan/rippy/issues/46)) ([98267ef](https://github.com/mpecan/rippy/commit/98267ef2a9154942212ea4d7eb310d8e2cb0c8c8))
* add direct hook installation for Claude Code, Gemini, and Cursor ([473e383](https://github.com/mpecan/rippy/commit/473e3838749da7199daa435e817daa712eb5e527))
* add direct hook installation for Claude Code, Gemini, and Cursor ([#41](https://github.com/mpecan/rippy/issues/41)) ([7a0a47d](https://github.com/mpecan/rippy/commit/7a0a47d8ed7975240c57c57df5bef219a59da98b))
* add docker export/save output flag handling ([#21](https://github.com/mpecan/rippy/issues/21)) ([f534238](https://github.com/mpecan/rippy/commit/f53423872adb1a90788418149115786c450e3e9d))
* add docker export/save output flag handling ([#31](https://github.com/mpecan/rippy/issues/31)) ([e52c615](https://github.com/mpecan/rippy/commit/e52c615babdd14a0d35147636865ffacccbe8154))
* add file content reading for informed classification ([#28](https://github.com/mpecan/rippy/issues/28)) ([6918740](https://github.com/mpecan/rippy/commit/69187401a1a8f9043fcb35272a17bbc6d091d003))
* add file content reading for informed classification ([#35](https://github.com/mpecan/rippy/issues/35)) ([db569b5](https://github.com/mpecan/rippy/commit/db569b5ecbc8539eeace4a9eadec00b2614de7fe))
* add file-access rule types (FileRead/FileWrite/FileEdit) ([#44](https://github.com/mpecan/rippy/issues/44)) ([e2cfa6f](https://github.com/mpecan/rippy/commit/e2cfa6f2cfeceb6b019d05a98a86ce8fb6de4abd))
* add flag alias discovery from command help output ([#63](https://github.com/mpecan/rippy/issues/63)) ([f18897a](https://github.com/mpecan/rippy/commit/f18897a89c53f1a55cf2918e0638720014c880b3))
* add flag alias discovery from command help output ([#63](https://github.com/mpecan/rippy/issues/63)) ([#65](https://github.com/mpecan/rippy/issues/65)) ([0f66bf6](https://github.com/mpecan/rippy/commit/0f66bf6caedcd08c188a49d881f52cf58486273e))
* add git workflow styles for configurable git permissiveness ([49ee7db](https://github.com/mpecan/rippy/commit/49ee7dbea1b354c2f374bc727eb1c4abd519f312))
* add git workflow styles for configurable git permissiveness ([#69](https://github.com/mpecan/rippy/issues/69)) ([a5393a7](https://github.com/mpecan/rippy/commit/a5393a7c702b6657fe0482a82fd93ee666653e0a))
* add path-aware mkdir handler and git repo-path scope checking ([#68](https://github.com/mpecan/rippy/issues/68)) ([109cb2d](https://github.com/mpecan/rippy/commit/109cb2d50e89c5f2eaedd7d48718d2bb54dba3b6))
* add path-aware mkdir handler, extract shared scope utilities ([75fbf9a](https://github.com/mpecan/rippy/commit/75fbf9ab622c5d6ec738242b8fbb66be18e8d32b))
* add project config trust model to prevent malicious .rippy files ([2a3b33f](https://github.com/mpecan/rippy/commit/2a3b33f2603db6a3dfee3cc05aa000f871a4ff38)), closes [#70](https://github.com/mpecan/rippy/issues/70)
* add project config trust model to prevent malicious .rippy files ([#79](https://github.com/mpecan/rippy/issues/79)) ([4579205](https://github.com/mpecan/rippy/commit/45792051e40b064acc7568bc16fbae6713f1d350))
* add proptest robustness suite for parsing and analysis surfaces ([#88](https://github.com/mpecan/rippy/issues/88)) ([e0b75be](https://github.com/mpecan/rippy/commit/e0b75be2b0cdc1af0a7d61e964706f37a8c3fea6))
* add Python inline source safety analysis ([#24](https://github.com/mpecan/rippy/issues/24)) ([0b3b42b](https://github.com/mpecan/rippy/commit/0b3b42b861ff6bc0f549cfa3cb78f686fe215d4b))
* add Python inline source safety analysis ([#34](https://github.com/mpecan/rippy/issues/34)) ([c9a8f58](https://github.com/mpecan/rippy/commit/c9a8f585f7b1be4fc3083b9c6815e108cd87b955))
* add Read/Write/Edit file access control with passthrough ([#54](https://github.com/mpecan/rippy/issues/54)) ([0aef9f9](https://github.com/mpecan/rippy/commit/0aef9f926da97fbbb48093fafbd2214287903864))
* add repo-level trust and TrustGuard for safe config modifications ([774e5de](https://github.com/mpecan/rippy/commit/774e5de3021d2c6f20307ef06573033fa4c4f14e))
* add rippy allow/deny/ask commands with pattern suggestion ([#47](https://github.com/mpecan/rippy/issues/47)) ([829b5cf](https://github.com/mpecan/rippy/commit/829b5cf141d8698afeaebe6bb9f51782291ad41f))
* add rippy debug command for decision tracing ([d2968b4](https://github.com/mpecan/rippy/commit/d2968b4ff37c5e62ae15696d7d6987658e927df2)), closes [#73](https://github.com/mpecan/rippy/issues/73)
* add rippy debug command for decision tracing ([#82](https://github.com/mpecan/rippy/issues/82)) ([5c93bef](https://github.com/mpecan/rippy/commit/5c93beff139d43d0bd5d6bb76eb024baa4f7a467))
* add rippy inspect command with list and trace modes ([#42](https://github.com/mpecan/rippy/issues/42)) ([4353966](https://github.com/mpecan/rippy/commit/4353966e68de4727ac2609ec7a2baa4f736a316c))
* add rippy list command for safe commands, handlers, and rules ([4578f1d](https://github.com/mpecan/rippy/commit/4578f1d854e257ac3c365598bc6d77ba874198f7)), closes [#76](https://github.com/mpecan/rippy/issues/76)
* add rippy list command for safe commands, handlers, and rules ([#93](https://github.com/mpecan/rippy/issues/93)) ([a957dc0](https://github.com/mpecan/rippy/commit/a957dc0293f04d7a51cc7eb9057e80834a7925b5))
* add rippy profile CLI commands (list, show, set) ([e45287e](https://github.com/mpecan/rippy/commit/e45287ee3b7508f81817ed709a41332f5481bb42)), closes [#99](https://github.com/mpecan/rippy/issues/99)
* add rippy profile CLI commands (list, show, set) ([#106](https://github.com/mpecan/rippy/issues/106)) ([f3f33dc](https://github.com/mpecan/rippy/commit/f3f33dc28f73b298f908ea9de7644c8a5e479f41))
* add rippy suggest with DB analysis and risk classification ([#48](https://github.com/mpecan/rippy/issues/48)) ([a48cf2e](https://github.com/mpecan/rippy/commit/a48cf2e0be1d33f70ec6a21faae8017e9c06783d))
* add rippy suggest with DB analysis and risk classification ([#48](https://github.com/mpecan/rippy/issues/48)) ([#60](https://github.com/mpecan/rippy/issues/60)) ([d8199e3](https://github.com/mpecan/rippy/commit/d8199e3593e8b8a5843b5c2a62b1531720e39a3f))
* add self_protect config field with set self-protect off escape hatch ([#45](https://github.com/mpecan/rippy/issues/45)) ([498e048](https://github.com/mpecan/rippy/commit/498e04899fcf064ba0624e648c7871d69fd695c7))
* add self_protect module with is_protected_path ([#45](https://github.com/mpecan/rippy/issues/45)) ([f2ba5d2](https://github.com/mpecan/rippy/commit/f2ba5d23d6a5cf0210d56c8aee5fb6a64b8a07c9))
* add self-protection for rippy config files ([#55](https://github.com/mpecan/rippy/issues/55)) ([fa50955](https://github.com/mpecan/rippy/commit/fa509550cb98181d046afca1f083da9aa2b16e9c))
* add session file parsing for rippy suggest ([#64](https://github.com/mpecan/rippy/issues/64)) ([43419e3](https://github.com/mpecan/rippy/commit/43419e31079f0288cf812c10745c4cac8b723672))
* add session file parsing for rippy suggest ([#64](https://github.com/mpecan/rippy/issues/64)) ([#66](https://github.com/mpecan/rippy/issues/66)) ([8d3b25d](https://github.com/mpecan/rippy/commit/8d3b25dfd6496c67af7aea1822a68269350ea956))
* add SQLite decision tracking and `rippy stats` command ([#52](https://github.com/mpecan/rippy/issues/52)) ([e358d9f](https://github.com/mpecan/rippy/commit/e358d9f4cb461c30516f79cf901163be55938312))
* add SQLite decision tracking and rippy stats command ([#43](https://github.com/mpecan/rippy/issues/43)) ([0caad1f](https://github.com/mpecan/rippy/commit/0caad1ff9555e6821b571122db84352b7cb83679))
* add structured command matching (command/subcommand/flags) ([#57](https://github.com/mpecan/rippy/issues/57)) ([#61](https://github.com/mpecan/rippy/issues/61)) ([32293bf](https://github.com/mpecan/rippy/commit/32293bfcc38af3878fef5fa05fde2a175ab7cd75))
* add structured command matching as alternative to glob patterns ([#57](https://github.com/mpecan/rippy/issues/57)) ([1398655](https://github.com/mpecan/rippy/commit/139865568742c8c3dc7e11be4115048814d45803))
* add TOML config format with rejection messages for AI guidance ([9c6ebd0](https://github.com/mpecan/rippy/commit/9c6ebd07ae15c81fec99df46a4519cba87aab866)), closes [#49](https://github.com/mpecan/rippy/issues/49)
* add TOML config format with rejection messages for AI guidance ([#50](https://github.com/mpecan/rippy/issues/50)) ([ba70bce](https://github.com/mpecan/rippy/commit/ba70bcebd7c89aa7adb02b8595eabdf922a9be96))
* add verbose mode, audit logging, depth limits, handler fixes ([2f28b7b](https://github.com/mpecan/rippy/commit/2f28b7be02d295d8c4fe9565320793f588a3c6df))
* add verbose mode, audit logging, depth limits, handler fixes ([ae0577b](https://github.com/mpecan/rippy/commit/ae0577b6f6ce5ef9780bc953c3cfc115ffca6bb3))
* check git -C/--git-dir/--work-tree paths against scope rules ([9ab7836](https://github.com/mpecan/rippy/commit/9ab78362d01966e39cb67d93800838fca5e3eaa9))
* complete recommended config with tests ([#16](https://github.com/mpecan/rippy/issues/16)) ([2582cf9](https://github.com/mpecan/rippy/commit/2582cf95508f900cd76a60aa3ad1b95f6cac5a78))
* complete recommended config with tests ([#25](https://github.com/mpecan/rippy/issues/25)) ([f49f1a3](https://github.com/mpecan/rippy/commit/f49f1a323b745f3867b8c718d7639fcab0e0b640))
* comprehensive cargo command classification ([a1cd248](https://github.com/mpecan/rippy/commit/a1cd248726e39c02fec2bf6fb65e0ae175dd88e9))
* comprehensive cargo command classification ([#37](https://github.com/mpecan/rippy/issues/37)) ([df117a9](https://github.com/mpecan/rippy/commit/df117a9580a6948b6b86af07a77dfc621e4bf6f1))
* **config:** add Config::load_from_str for in-memory parsing ([a35b4e8](https://github.com/mpecan/rippy/commit/a35b4e84effff29fed1d2d38b02ea055c54533f9)), closes [#77](https://github.com/mpecan/rippy/issues/77)
* create package TOML files (review, develop, autopilot) ([#104](https://github.com/mpecan/rippy/issues/104)) ([9240156](https://github.com/mpecan/rippy/commit/9240156a8204e34c4b5104d731109d32d27b5d3e))
* create package TOML files and packages module ([63c694b](https://github.com/mpecan/rippy/commit/63c694bc26318bb48aa21a1fbb056eacd6e56ca4)), closes [#97](https://github.com/mpecan/rippy/issues/97)
* data-driven security test suite with Environment struct ([a604948](https://github.com/mpecan/rippy/commit/a604948a56303805b95c1999b8f21cf163aa726c))
* data-driven security test suite with Environment struct ([#94](https://github.com/mpecan/rippy/issues/94)) ([9918c82](https://github.com/mpecan/rippy/commit/9918c82b241b399beb865a8dd9e9b545ac2a7585))
* deeper sed and awk program analysis ([#20](https://github.com/mpecan/rippy/issues/20)) ([5e15407](https://github.com/mpecan/rippy/commit/5e15407dd35f7d5c11d25c30739cc1c0b6b8d867))
* deeper sed and awk program analysis ([#30](https://github.com/mpecan/rippy/issues/30)) ([ad270a1](https://github.com/mpecan/rippy/commit/ad270a1b9cc647690d471080f6c5793b1a1d5adf))
* default to session files instead of tracking DB for suggest ([232df19](https://github.com/mpecan/rippy/commit/232df191b0e33c46a68a2e26343cd373fd36c382))
* detect all 5 weakening heuristics in project config ([8b7cd6f](https://github.com/mpecan/rippy/commit/8b7cd6f92b2c3425764b0ab710cef07aaa62b6f7))
* expand inline code safety analysis to Node.js, Ruby, and Perl ([cb7d3ee](https://github.com/mpecan/rippy/commit/cb7d3ee1596d01a33b36e6f80b0d77107dd063de)), closes [#75](https://github.com/mpecan/rippy/issues/75)
* expand inline code safety analysis to Node.js, Ruby, and Perl ([#92](https://github.com/mpecan/rippy/issues/92)) ([19f85d9](https://github.com/mpecan/rippy/commit/19f85d9c6fa7f5de6dc5388d256612081a525bc7))
* extract file_path and FileOp from Read/Write/Edit payloads ([#44](https://github.com/mpecan/rippy/issues/44)) ([08ae90a](https://github.com/mpecan/rippy/commit/08ae90a47cac6d10a2d93780408bdfeb52652ed7))
* implement full Dippy-compatible shell command safety hook ([d1737d3](https://github.com/mpecan/rippy/commit/d1737d39c416d6d6c5cd08c39a3b179f42d140c3))
* initial project scaffold ([5c320b7](https://github.com/mpecan/rippy/commit/5c320b7a9b8d8b36898cedc3be2aaf3df4a64403))
* integrate package loading into config loader ([#105](https://github.com/mpecan/rippy/issues/105)) ([3cd5d0a](https://github.com/mpecan/rippy/commit/3cd5d0a0f236d5cc7122477d3053901dd54aca6e))
* integrate package loading into config pipeline ([751a675](https://github.com/mpecan/rippy/commit/751a67537155bdfb4e375d8d9490b1c538075bcc)), closes [#98](https://github.com/mpecan/rippy/issues/98)
* integrate package selection into rippy init ([2904d02](https://github.com/mpecan/rippy/commit/2904d0248c25db6b2b6575608b44b8c33a9519ac)), closes [#100](https://github.com/mpecan/rippy/issues/100)
* integrate package selection into rippy init ([#108](https://github.com/mpecan/rippy/issues/108)) ([1e5fe0e](https://github.com/mpecan/rippy/commit/1e5fe0ec63f73b9e9f43f07a411a7c74192484e4))
* migrate pure classification handlers to config-driven stdlib ([#58](https://github.com/mpecan/rippy/issues/58)) ([e9a6fe6](https://github.com/mpecan/rippy/commit/e9a6fe66cd1632e9282c3d92c7cf15029aa36b63))
* migrate pure classification handlers to config-driven stdlib ([#58](https://github.com/mpecan/rippy/issues/58)) ([#62](https://github.com/mpecan/rippy/issues/62)) ([c249b05](https://github.com/mpecan/rippy/commit/c249b05be2ebc25d69c4685acb93c42971582cb7))
* read Claude Code permission rules for informed decisions ([da6d253](https://github.com/mpecan/rippy/commit/da6d253f075e959735b3d004c9351a246dbf6c5e))
* read Claude Code permission rules for informed decisions ([#36](https://github.com/mpecan/rippy/issues/36)) ([75b6642](https://github.com/mpecan/rippy/commit/75b6642e802f3f0dc3ef8b02c3eb653e6f4be674))
* recognize safe heredoc-in-command-substitution patterns ([f548438](https://github.com/mpecan/rippy/commit/f54843837b43983b41ade61a4efa26127deec245)), closes [#95](https://github.com/mpecan/rippy/issues/95)
* recognize safe heredoc-in-command-substitution patterns ([#96](https://github.com/mpecan/rippy/issues/96)) ([b282561](https://github.com/mpecan/rippy/commit/b282561d4cbfefd847bcfcf9fe5b45bd0f9a693f))
* refactor Rule system + wire conditional when clauses ([#46](https://github.com/mpecan/rippy/issues/46)) ([ddcc2a1](https://github.com/mpecan/rippy/commit/ddcc2a1c9b9e33fafdb254e8b56e94811688dca4))
* refactor Rule system to flat struct + add conditional when clauses ([#56](https://github.com/mpecan/rippy/issues/56)) ([82f3875](https://github.com/mpecan/rippy/commit/82f38758c49c3f226f8e73088f0cb3085cc4c7be))
* remote flag, heredocs, perf, 49 new tests ([#5](https://github.com/mpecan/rippy/issues/5), [#6](https://github.com/mpecan/rippy/issues/6), [#7](https://github.com/mpecan/rippy/issues/7), [#8](https://github.com/mpecan/rippy/issues/8)) ([7e273ac](https://github.com/mpecan/rippy/commit/7e273ac6c391dbc3f12203a52cfef694d1b715ea))
* remote flag, heredocs, perf, expanded tests ([77de944](https://github.com/mpecan/rippy/commit/77de944c411259d9d8a9058d3cde3a122789c503))
* update setup matchers for file-access hooks ([#44](https://github.com/mpecan/rippy/issues/44)) ([0ebb17e](https://github.com/mpecan/rippy/commit/0ebb17e5f1dbd93e60e904dababc1816a94eb76b))
* upgrade gh handler with API method and GraphQL analysis ([#18](https://github.com/mpecan/rippy/issues/18)) ([626490b](https://github.com/mpecan/rippy/commit/626490b76919793e3854ebe1fb02ca85ea9e5f28))
* upgrade gh handler with API method and GraphQL analysis ([#27](https://github.com/mpecan/rippy/issues/27)) ([fb65331](https://github.com/mpecan/rippy/commit/fb65331e77e99e1d732d020509dd6b2bbdaeb422))
* wire file-access evaluation into hook path with passthrough ([#44](https://github.com/mpecan/rippy/issues/44)) ([32892da](https://github.com/mpecan/rippy/commit/32892daf7284d42a72d1f165469d6f6a2a8bad39))
* wire self-protection into file tools and Bash redirects ([#45](https://github.com/mpecan/rippy/issues/45)) ([3ee5bcb](https://github.com/mpecan/rippy/commit/3ee5bcb2ac9dd81351fd08b2a63d57ae4e9bea37))


### Bug Fixes

* address review findings — add missing tests, remove unreachable!() ([6ad3a0a](https://github.com/mpecan/rippy/commit/6ad3a0a6c52be7a77c2308c6837048f52c6dccd2))
* address review findings for config weakening warnings ([82ad2d7](https://github.com/mpecan/rippy/commit/82ad2d741d9a90c8a7bbf43304e600d5513adf66))
* address review items for flag discovery ([40a64ad](https://github.com/mpecan/rippy/commit/40a64ada37a3b7ca15b36f1f325f5f919d673cd5))
* address review items for rippy suggest ([f13a8dc](https://github.com/mpecan/rippy/commit/f13a8dc27baef10146d7aeabd69ea6c757a5a113))
* address review items for session suggest ([1c472ab](https://github.com/mpecan/rippy/commit/1c472ab28c73afbcb3e600d6710cf00659bcd14b))
* address review items for structured matching ([7f21ee4](https://github.com/mpecan/rippy/commit/7f21ee4fa433ca291b2115b28a5cef29daa66185))
* address review minor items — quoted heredoc test, normalize_stars cleanup ([c860abe](https://github.com/mpecan/rippy/commit/c860abe0767582543c00a3376e682b677500d46b))
* change deny to ask in recommended config for user-approvable commands ([7ecd89b](https://github.com/mpecan/rippy/commit/7ecd89b7ae22b09ab094e8a994bdbcdbe98600a0))
* close safety bypasses, add README, improve DX ([ba30708](https://github.com/mpecan/rippy/commit/ba30708a6dfedb35f8809fd3336f99f0422bde3d))
* correct dependency comment and add missing cargo tests ([aaa61b6](https://github.com/mpecan/rippy/commit/aaa61b648ddcd31d2a11bb2f8ef0e90dc24387b4))
* derive prompt indices from Package::all() and add invalid package test ([6e5f4f6](https://github.com/mpecan/rippy/commit/6e5f4f6116feb2a6c4a4d90242804d80217070a5))
* detect backtick command substitution in SIMPLE_SAFE args ([0d6defc](https://github.com/mpecan/rippy/commit/0d6defc5e2805b009be0c3cc35b5d556b04f46f6)), closes [#90](https://github.com/mpecan/rippy/issues/90)
* detect backtick command substitution in SIMPLE_SAFE args ([#91](https://github.com/mpecan/rippy/issues/91)) ([9eb54ab](https://github.com/mpecan/rippy/commit/9eb54ab9a5f9b695e9a488241633d6793b233246))
* extract suggest into standalone subcommand and fix review items ([14ca41e](https://github.com/mpecan/rippy/commit/14ca41ed4a40c075eb875645c36785dd60c66e43))
* filter out commands already auto-allowed by CC permissions or config ([5356dd5](https://github.com/mpecan/rippy/commit/5356dd56ad65c07b612964d815a24d95a2d06cc7))
* format test code to match CI rustfmt ([e4c5069](https://github.com/mpecan/rippy/commit/e4c5069a1def88c6b5d239a1841332f4ea4861a6))
* gh api --input always asks (cannot verify file contents) ([b9d0e5c](https://github.com/mpecan/rippy/commit/b9d0e5c75bcc4ad2baec8a20bd72897d3483abdf))
* make detect_git_branch test CI-safe ([#46](https://github.com/mpecan/rippy/issues/46)) ([29f92b7](https://github.com/mpecan/rippy/commit/29f92b7805b7d34d7ecd4aade36eda990261b836))
* move fd, dmesg, ip, ifconfig from SIMPLE_SAFE to handlers ([#17](https://github.com/mpecan/rippy/issues/17)) ([f9a0d30](https://github.com/mpecan/rippy/commit/f9a0d30e7f6762e859516d323c750d3fca2ca790))
* move fd, dmesg, ip, ifconfig from SIMPLE_SAFE to handlers ([#26](https://github.com/mpecan/rippy/issues/26)) ([4f4a9d5](https://github.com/mpecan/rippy/commit/4f4a9d560ec899983de69a1ec524592f506380eb))
* preserve --help/--version allow for migrated handlers ([a242184](https://github.com/mpecan/rippy/commit/a2421848cd5404e1f3aa44fb880c6330d98d2961))
* reduce false positives in sed w and awk pipe detection ([678b365](https://github.com/mpecan/rippy/commit/678b365d086c4f11909b2e7d87584a7a1326d718))
* remove dead export/save entries from SAFE list ([a476ca4](https://github.com/mpecan/rippy/commit/a476ca41f2cbb061ac6689def909cc526930e973))
* remove extra whitespace in self-protect deny message ([#45](https://github.com/mpecan/rippy/issues/45)) ([de92007](https://github.com/mpecan/rippy/commit/de920071e1f69472c579c6d1d37619bc2dd0d9c3))
* rename binary from rippy to rppy to avoid crates.io conflict ([5991859](https://github.com/mpecan/rippy/commit/5991859fd4b963817bb84e7c39442d0f25002f42))
* rename crate to rippy-cli, binary stays rippy ([de43c4b](https://github.com/mpecan/rippy/commit/de43c4ba9278989f2927cdc77bdc39395e91b674))
* tighten package setting line match to prevent false positives ([ed4fa77](https://github.com/mpecan/rippy/commit/ed4fa77bbea7ad39ded24ae32831a40974da30ac))
* tighten package setting line match to prevent false positives ([#109](https://github.com/mpecan/rippy/issues/109)) ([5219ad0](https://github.com/mpecan/rippy/commit/5219ad077ed4545be7f2e840bdaa7bafff42eaaf))
* use parameterized SQL queries in tracking module ([#43](https://github.com/mpecan/rippy/issues/43)) ([cc2561e](https://github.com/mpecan/rippy/commit/cc2561ed09496c5403efcc836b91ba68f0d2bae4))


### Performance Improvements

* partition config rules by type, add literal pattern fast path ([de68b0a](https://github.com/mpecan/rippy/commit/de68b0a819ead640f15d3013de23582ae864462d))
* partition config rules, literal pattern fast path ([90dacac](https://github.com/mpecan/rippy/commit/90dacac6e8418fe3c96d9c90af77b0ee158f1827))


### Documentation

* add package system documentation and update README ([4f639d8](https://github.com/mpecan/rippy/commit/4f639d8abd6879bd90b211385a38bf22c65cea03)), closes [#101](https://github.com/mpecan/rippy/issues/101)
* add security model and limitations section to README ([eaadbc2](https://github.com/mpecan/rippy/commit/eaadbc2624de895b8b510e50e268d1dd8afb2658)), closes [#71](https://github.com/mpecan/rippy/issues/71)
* add security model and limitations section to README ([#80](https://github.com/mpecan/rippy/issues/80)) ([ecc1a26](https://github.com/mpecan/rippy/commit/ecc1a26d46fe9d770cc21309f93b27be8754b61a))
* add setup tokf to CLI table and test example TOML parsing ([8f9f0fc](https://github.com/mpecan/rippy/commit/8f9f0fcc4ecdd936992ccee678640c5ca79a26c6))
* clarify Claude Code settings are a separate pre-analysis check ([a1a2dc2](https://github.com/mpecan/rippy/commit/a1a2dc2db7d29e044c3ac4f629a2b340974801a6))
* mention proptest robustness tests in CLAUDE.md ([45327a1](https://github.com/mpecan/rippy/commit/45327a199ea5b644cd7c8bd32aba41ef4dc70fcb)), closes [#77](https://github.com/mpecan/rippy/issues/77)
* package system documentation and README updates ([#110](https://github.com/mpecan/rippy/issues/110)) ([dd08553](https://github.com/mpecan/rippy/commit/dd08553555ce3eb83ef9beab1dad266fefa9808a))
* prepare for first release ([de7a55b](https://github.com/mpecan/rippy/commit/de7a55b8e55f9257f058f3995cacf3ed60fb555f))
* prepare for first release ([#39](https://github.com/mpecan/rippy/issues/39)) ([d7ff3aa](https://github.com/mpecan/rippy/commit/d7ff3aa34167616bd992bccbc814d6d902ae5db0))


### Code Refactoring

* address review findings on proptest robustness suite ([8bf29d0](https://github.com/mpecan/rippy/commit/8bf29d0a83055afaf626a04b706cc8099fecf0f3)), closes [#77](https://github.com/mpecan/rippy/issues/77)
* cleanup from code review ([9338a68](https://github.com/mpecan/rippy/commit/9338a681ad36e03a8eab65db5b0420d6866d8da7))
* **config:** convert config.rs to config/ directory module ([3ba94a9](https://github.com/mpecan/rippy/commit/3ba94a96e67a47de956228840fbf3ca67f823224))
* **config:** extract parser, matching, and sources submodules ([59c765a](https://github.com/mpecan/rippy/commit/59c765aafda3ea6908048f016e19f196b63793df))
* **config:** extract types, loader; relocate tests to their modules ([c3894dc](https://github.com/mpecan/rippy/commit/c3894dcd08a3cf51e2e6d009fa8121da5fae5dea))
* deduplicate action string logic via Rule::action_str() ([#46](https://github.com/mpecan/rippy/issues/46)) ([b95101c](https://github.com/mpecan/rippy/commit/b95101cc94b19d48cb315ef24952ae2c2ba543c3))
* expose config internals needed by inspect command ([#42](https://github.com/mpecan/rippy/issues/42)) ([0bccbb1](https://github.com/mpecan/rippy/commit/0bccbb188e5d1cd21216070535341f236ae569c0))
* extract is_expansion_node predicate, unify expansion detection ([945f6bb](https://github.com/mpecan/rippy/commit/945f6bb0d45dc1582f561ccfabb56bfc090a5bb6))
* **handlers:** split misc.rs into themed handler modules ([3d9cfb6](https://github.com/mpecan/rippy/commit/3d9cfb608c9f6158296f1f26b1e757dc83f98f23))
* improve code reviewability and maintainability ([#83](https://github.com/mpecan/rippy/issues/83)) ([1cda6fe](https://github.com/mpecan/rippy/commit/1cda6fe8bc3ca8b8b9c2b207e76fd7888582fc84))
* replace tree-sitter-bash with rable parser ([56a681b](https://github.com/mpecan/rippy/commit/56a681bee118fcb8b8698de4b172c35a7c885594))
* replace tree-sitter-bash with rable parser ([#38](https://github.com/mpecan/rippy/issues/38)) ([a7a10fe](https://github.com/mpecan/rippy/commit/a7a10fef55d7f7a804466ece3f08b42a50c500f0))
* simplify rable migration after code review ([5022cc3](https://github.com/mpecan/rippy/commit/5022cc394e0f51769eaf6f06273671e3d63ccad5))
* simplify test infrastructure after code review ([5868f5a](https://github.com/mpecan/rippy/commit/5868f5af1a32d98155dc7784be3e831bb7cc4d3f))
* simplify weakening detection — deduplicate, pre-compute, use Range ([0be613d](https://github.com/mpecan/rippy/commit/0be613dbcbb1ce77b99c3ee9a3aa442ba97b36b3))
* split stdlib into per-tool TOML files ([71e7c5d](https://github.com/mpecan/rippy/commit/71e7c5d6a43a893383a0a8e52fbe051509139332))
* **tests:** split monolithic integration.rs into 10 themed test files ([f543b01](https://github.com/mpecan/rippy/commit/f543b01dbf95d2feb5e84e26c27dee0c7489efa3))
* use rkyv for flag cache serialization ([565eba3](https://github.com/mpecan/rippy/commit/565eba3b26d45a9bdc20caed916aad9fed2ea135))
