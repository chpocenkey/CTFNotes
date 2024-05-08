`objdump -h func.so`
查看 `func.so` 文件中的段信息

`readelf -r func.so | grep tmp`
查找变量 `tmp` 在 `func.so` 文件中的位置

`objdump -d -M intel --section=.text func.so | grep -A 20 "<func>"`
显示前 20 行 `func.so` 文件中 `.text` 段中 `func` 函数的 `intel` 格式汇编