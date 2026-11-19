# Module corpus

Real modules as their authors publish them, byte for byte, each pinned to an upstream commit. Each
`<module>.expect.json` beside them is how Concord reads that module, and the test compares the two.

The files below are kept here under their own licences. `LICENSE-app2smile` and `LICENSE-maasea` are
the MIT and Apache-2.0 texts of the repositories so marked; the GPL-3.0 ones fall under the
repository's own licence text.

| File | Source | Licence |
|---|---|---|
| `fmz200-AffiliateMarketing.sgmodule` | https://raw.githubusercontent.com/fmz200/wool_scripts/eca3853dfed0f2db829408a81b98ff279bcfe8f9/Surge/module/split/part!!/AffiliateMarketing.sgmodule | GPL-3.0 |
| `fmz200-bilibili.sgmodule` | https://raw.githubusercontent.com/fmz200/wool_scripts/eca3853dfed0f2db829408a81b98ff279bcfe8f9/Surge/module/split/partB/bilibili.sgmodule | GPL-3.0 |
| `fmz200-Zhihu.sgmodule` | https://raw.githubusercontent.com/fmz200/wool_scripts/eca3853dfed0f2db829408a81b98ff279bcfe8f9/Surge/module/split/partZ/Zhihu.sgmodule | GPL-3.0 |
| `fmz200-KuaiDi100.sgmodule` | https://raw.githubusercontent.com/fmz200/wool_scripts/eca3853dfed0f2db829408a81b98ff279bcfe8f9/Surge/module/split/partK/KuaiDi100.sgmodule | GPL-3.0 |
| `fmz200-Taobao.sgmodule` | https://raw.githubusercontent.com/fmz200/wool_scripts/eca3853dfed0f2db829408a81b98ff279bcfe8f9/Surge/module/split/partT/Taobao.sgmodule | GPL-3.0 |
| `app2smile-bilibili.sgmodule` | https://raw.githubusercontent.com/app2smile/rules/df6366a7024e0b3f0aa3510c5b791eea6f3cba89/module/bilibili.sgmodule | MIT |
| `app2smile-tieba.sgmodule` | https://raw.githubusercontent.com/app2smile/rules/df6366a7024e0b3f0aa3510c5b791eea6f3cba89/module/tieba.sgmodule | MIT |
| `maasea-Bilibili.Helper.sgmodule` | https://raw.githubusercontent.com/Maasea/sgmodule/65075cdb388fc5e3094afd7e7314c67b243f3525/Bilibili.Helper.sgmodule | Apache-2.0 |
| `maasea-YouTube.Enhance.sgmodule` | https://raw.githubusercontent.com/Maasea/sgmodule/65075cdb388fc5e3094afd7e7314c67b243f3525/YouTube.Enhance.sgmodule | Apache-2.0 |
| `maasea-WeRead.sgmodule` | https://raw.githubusercontent.com/Maasea/sgmodule/65075cdb388fc5e3094afd7e7314c67b243f3525/WeRead.sgmodule | Apache-2.0 |
| `maasea-URLRewrite.sgmodule` | https://raw.githubusercontent.com/Maasea/sgmodule/65075cdb388fc5e3094afd7e7314c67b243f3525/URLRewrite.sgmodule | Apache-2.0 |
| `rstore-Remote_Cookies.sgmodule` | https://raw.githubusercontent.com/zirawell/R-Store/d0f4dd305bade7cc6a38e3445a768d72aaea0e5b/Rule/Surge/Plugin/Remote_Cookies.sgmodule | GPL-3.0 |
| `rstore-vvebo.sgmodule` | https://raw.githubusercontent.com/zirawell/R-Store/d0f4dd305bade7cc6a38e3445a768d72aaea0e5b/Rule/Surge/Plugin/vvebo.sgmodule | GPL-3.0 |
| `rstore-DivineEngine.sgmodule` | https://raw.githubusercontent.com/zirawell/R-Store/d0f4dd305bade7cc6a38e3445a768d72aaea0e5b/Rule/Surge/Redirect/DivineEngine.sgmodule | GPL-3.0 |
| `rstore-allAdBlock.sgmodule` | https://raw.githubusercontent.com/zirawell/R-Store/d0f4dd305bade7cc6a38e3445a768d72aaea0e5b/Rule/Surge/Adblock/All/allAdBlock.sgmodule | GPL-3.0 |
| `rstore-adunion.sgmodule` | https://raw.githubusercontent.com/zirawell/R-Store/d0f4dd305bade7cc6a38e3445a768d72aaea0e5b/Rule/Surge/Adblock/App/%23/%E5%B9%BF%E5%91%8A%E8%81%94%E7%9B%9F/adunion.sgmodule | GPL-3.0 |
| `sparkle-bilibili.sgmodule` | https://raw.githubusercontent.com/kokoryh/Sparkle/0eb4fd1c0c30e7aeaab6c70f5ec546a34f3c9d81/release/surge/module/bilibili.sgmodule | GPL-3.0 |
| `sparkle-weibo-intl.sgmodule` | https://raw.githubusercontent.com/kokoryh/Sparkle/0eb4fd1c0c30e7aeaab6c70f5ec546a34f3c9d81/release/surge/module/weibo-intl.sgmodule | GPL-3.0 |
| `sparkle-youtube.sgmodule` | https://raw.githubusercontent.com/kokoryh/Sparkle/0eb4fd1c0c30e7aeaab6c70f5ec546a34f3c9d81/release/surge/module/youtube.sgmodule | GPL-3.0 |
| `sparkle-scheduled-tasks.sgmodule` | https://raw.githubusercontent.com/kokoryh/Sparkle/0eb4fd1c0c30e7aeaab6c70f5ec546a34f3c9d81/release/surge/module/scheduled-tasks.sgmodule | GPL-3.0 |
| `chavy-boxjs.rewrite.surge.sgmodule` | https://raw.githubusercontent.com/chavyleung/scripts/bfab3c906f3d5d126e9094f15730e025f7f32128/box/rewrite/boxjs.rewrite.surge.sgmodule | GPL-3.0 |
| `chavy-surge.cookies.sgmodule` | https://raw.githubusercontent.com/chavyleung/scripts/bfab3c906f3d5d126e9094f15730e025f7f32128/surge.cookies.sgmodule | GPL-3.0 |
| `chavy-jd.618.sgmodule` | https://raw.githubusercontent.com/chavyleung/scripts/bfab3c906f3d5d126e9094f15730e025f7f32128/jd/jd.618.sgmodule | GPL-3.0 |

`remote.json` lists modules from repositories that declare no licence compatible with
GPL-3.0-or-later, by URL and SHA-256 only. `cargo xtask module-corpus` downloads them into
`target/module-corpus` and checks each digest; their expectations are kept here all the same.
