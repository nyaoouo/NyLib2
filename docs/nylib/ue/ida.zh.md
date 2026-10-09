> 本文档为 ida.md 的中文阅读副本；英文版为权威来源（canonical）。

<!-- dt:meta v="1" lang="zh" source="ida.md" -->

<!-- dt:section id="__preamble__" hash="a74e31a29964" -->
# IDA 导入器

[索引](index.md) · 代码：`scripts/ida/ue_dumper_import.py`

`scripts/ida/ue_dumper_import.py` 将快照导入 IDA 9.x 数据库。它只使用 Python 标准库，因此 IDA 不需要 nylib。

<!-- dt:section id="run-it-0" hash="d7f16937da84" -->
## 运行它

1. 在 IDA 9.x 中打开游戏的 exe，或快照的 `image/<exe>`（参见 [Dump](dump.md#exports)），并等待自动分析完成。
2. File > Script file（Alt+F7） > `scripts/ida/ue_dumper_import.py`。会弹出一个对话框询问快照文件夹和选项；按 Import。

其他方式：

- 插件：把文件复制到 IDA 的 `plugins` 文件夹，然后 Edit > Plugins > UE Dumper Import（Ctrl-Alt-U；这个快捷键尚未测试）。
- 批处理，不使用 GUI：

  ```text
  idat -A -S"scripts/ida/ue_dumper_import.py --snapshot <snapshot folder> --types all" <database>
  ```

  选项：`--types all|referenced|none`、`--roots A,B`（配合 `referenced`）、`--no-exec`、`--no-vtables`、`--no-globals`、`--no-core-types`、`--no-enums`、`--no-comments`、`--overwrite`、`--force`、`-v`。退出码：0 完成，1 错误，2 用法错误，3 拒绝构建。
- 在 IDA 的 Python 控制台中，把脚本所在文件夹加入 `sys.path`：`import ue_dumper_import as uei; uei.run(r'<snapshot folder>')`。

<!-- dt:section id="what-it-applies-0" hash="7c4fbe9bc911" -->
## 它应用了什么

- 名称：原生 UFunction 的执行函数、虚表，以及全局变量 `GObjects`、`GNames`、`GWorld`、`ProcessEvent`、`AppendString`。
- 类型：引擎核心类型、枚举，以及类和结构体（全部、仅根引用到的、或不包含任何）。
- 注释：在每个 UFunction 的执行函数上标注其签名和标志。

它首先检查数据库是否由快照的 exe 构建而成（SHA-256，或 PE 时间戳和大小），除非你确认（`--force`），否则会拒绝另一个构建。再次运行会保留你手动修改过的名称、类型和注释，并列出这些内容；`--overwrite`（对话框中的"覆盖我手动修改的内容"）会替换它们。
