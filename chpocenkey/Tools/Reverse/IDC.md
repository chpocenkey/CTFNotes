## 简介

IDC 是 IDA Pro 中的一种脚本语言，用于自动化处理和操作反汇编的二进制文件

语法规则类似与 C 语言，但更简单易学

## 基本语法

这里简要总结 IDC 的基础语法，包括变量定义、条件语句、循环语句等，更多细节可以参考 《IDA Pro 权威指南》

- 结束：IDC 语句以 `;` 结束
- 注释：IDC 使用 `//` 或 `/**/` 作为注释
- 变量：IDC 中所有变量都被定义为 `auto` 类型，会自动进行类型转换
	- IDC 用 `auto` 关键字引入一个局部变量的申明，用 `extern` 关键字引入全局变量的申明
- 运算：IDC 几乎支持 C 语言中的所有运算和逻辑操作符，所有整数操作数均作为有符号数处理
- 输出：IDC 中使用 `Message` 函数作为输出，类似于 C 语言中的 `printf` 函数

## API 函数

IDC 提供了大量访问 IDA 数据库的 API，通过这些函数才能实现与 IDA 的交互，从而编写有用的脚本

**读取和修改数据的函数**

```C
long Byte(long addr) //从虚拟地址addr中读取一个字节值
long Word(long addr) //从虚拟地址addr中读取一个字（2字节）值
long Dword(long addr) //从虚拟地址addr中读取一个双字（4字节）值
void PatchByte(long addr, long val) //设置虚拟地址addr处的一个字节值
void PatchWord(long addr, long val) //设置虚拟地址addr处的一个字值
void PatchDword(long addr, long val) //设置虚拟地址addr处的一个双字值
bool isLoaded(long addr) //如果addr包含有效数据，则返回1，否则0
```

**用户交互函数**

```C
void Message(string format, ...) // 格式化打印。接受printf风格的格式化字符串
void print(...) // 在输出窗口打印每个参数的字符串表示形式
void Wording(string format, ...) // 对话框中显示一条格式化信息
string AskStr(string default, string prompt) // 显示一个输入框，要求用户输入一个额字符串值。如果操作成功，则返回用户的字符串；如果对话框被取消，则返回0
string AskFile(long doSave, string mask, string prompt) // 显示一个文件选择对话框，以简化选择文件的任务。新文件保存数据(doSave=1)，或选择现有的文件读取数据(doSave=0)。可以根据mask（如*.*或*.idc）过滤显示的文件列表。如果操作成功，则会返回选定文件的名称；如果对话框被取消，返回0
string AskYN(long default, string prompt) // 用是或否的问题提示用户。突出一个默认的答案（1为是，0为否，-1为取消）。返回值是一个选定答案的整数。
long ScreenEA() // 返回当前光标所在位置的虚拟地址
bool Jump(long addr) // 跳转到反汇编窗口的指定地址
```

**字符串操作函数**

```C
string form(string format, ...) //类似c语言的sprintf函数，返回一个新年字符串，该字符串根据所提供的格式化字符串和值进行格式化
string sprintf(string format, ...) //IDA5.6+ sprintf用于替代form
long atol(string val) //将十进制值val转化成对应的整数值
long xtol(string val) //将十六进制值val（可选择以0x开头）转换成对应的整数值
string ltoa(long val, long radix) //以指定的radix(2、8、10或16)返回val的字符串值
string ord(string ch) //返回单字符字符串ch的ASCII值
long strlen(string str) //返回所提供字符串的长度
long strstr(string str, string substr) //返回str中substr的索引，如果没有发现子字符串，则返回-1
string substr(string str, long start, long end) //返回包含str中由start到end-1位置的字符的子字符串。如果使用分片，此字符串等同于str[start:end]
```

**文件输入/输出函数**

```C
long fopen(string filename, string mode) //返回一个整数文件句柄（如果发生错误，则返回0），供所有IDC文件 输入/输出函数使用。mode参数与C语言的fopen函数使用相同的模式(r,w,等)
void fclose(long handle) //关闭fopen中文件句柄指定的文件
void filelength(long handle) //返回指定文件的长度，如果发生错误，则返回-1
long fgetc(long handle) //从给定文件中读取一个字节。如果发生错误，则返回-1
long fputc(long val, long handle) //写入一个字节到指定文件中，如果操作成功，则返回0；如果发生错误，则返回-1
long fprintf(long handle, string format, ...) //将格式化字符串写入到指定文件中
long writestr(long handle, string str) //将指定的字符串写入到给定文件中
string/long readstr(long handle) //从给定文件中读取一个字符串。这个函数读取到下一个换行符位置的所有字符（包括非ASCII字符），包括换行符本身（ASCII 0x0a）。操作成功，返回字符串；如果读到文件结尾，则返回-1
long writelong(long handle, long val, long bigendian) //使用大端(bigendian=1)或小端(bigendian=0)字节顺序将一个4字节整数写入到指定文件
long readlong(long handle, long bigendian) //使用大端(bigendian=1)或小端(bigendian=0)字节顺序从给定文件中读取一个4字节整数
long writeshort(long handle, long val, long bigendian) //使用大端(bigendian=1)或小端(bigendian=0)字节顺序将一个2字节整数写入到指定文件
long readshort(long handle, long bigendian) //使用大端(bigendian=1)或小端(bigendian=0)字节顺序从给定文件中读取一个2字节整数
bool loadfile(long handle, long pos, long addr, long length) //从给定文件的pos位置读取length数量的字节，并将这些字节写入到以addr地址开头的数据库中
bool savefile(long handle, long pos, long addr, long length) //将以addr数据库地址开头的length数量的字节写入到给定文件的pos位置
```

**操纵数据库的函数**

```C
string Name(long addr) //返回与给定地址有关的名称，如果该位置没有名称，则返回空字符串。如果名称被标记为局部名称，这个函数并不敢回用户定义的名称
string NameEx(long from, long addr) //返回与addr有关的名称。如果该位置没有名称，则返回空字符串。如果from是一个同样包含addr的函数中的地址，则这个函数返回用户定义的局部名称。
bool MakeNameEx(long addr, string name, long flags) //将给定的名称分配给给定的地址。改名称使用flags位掩码中指定的属性创建而成。这些标志在帮助系统中的MakeNameEx文档中记载描述，可以用于指定各种属性，如名称是局部名称还是公共名称、名称是否应在名称窗口中列出。
long LockByName(string name) //返回一个位置（名称已给定）的地址。如果数据库中没有该名称，则返回BADADDR(-1)
long LockByNameEx(long funcaddr, string localname) //在包含funcaddr的函数中搜索给定的局部名称。如果给定的函数中没有这个名称，则返回BADADDR（-1）
```

**处理函数的函数**

```C
long GetFunctionAttr(long addr, long attrib) //返回包含给定地址的函数的被请求的属性。文档中有属性常量。如要查找一个函数的结束地址，可以使用GetFunctionAttr(addr, FUNCTION_END)
string GetFunctionName(long addr) //返回包含给定地址的函数的名称。如果给定地址并不属于一个函数，则返回一个空字符串
long NextFunction(long addr) //返回给定地址后的下一个函数的起始地址。如果数据库中给定地址后没有其他函数，则返回-1
long PrevFunction(long addr) //返回给定地址之前距离最近的函数的起始地址。如果数据库中给定地址后没有其他函数，则返回-1
```

**代码交叉引用函数**

```C
long Dfirst(long from) //返回给定地址引用一个数据值得第一个位置。如果给定地址没有引用其他地址，则返回BADADDR
long Dnext(long from, long current) //如果current已经在前一次调用Dfirst或Dnext时返回，则返回给定地址(from)向其引用一个数据值的下一个位置。如果没有其他交叉引用存在，则返回BADADDR
long XrefType() //返回一个常量，说明某个交叉引用查询函数（如Dfirst）返回的最后一个交叉引用的类型。对于数据交叉引用，这些常量包括dr_0（提供的偏移量）、dr_w（数据写入）和dr_R（数据读取）
long DfirstB(long to) //返回将给定地址作为数据引用的第一个位置。如果不存在引用给定地址的交叉引用，则返回BADADDR
long DnextB(long to, long current) //如果current已经在前一次调用DfirstB或DnextB时返回，则返回将给定地址（to）作为数据引用的下一个位置。如果没有其他对给定地址的交叉引用存在，则返回BADADDR
```

**数据交叉引用函数**

```C
long Dfirst(long from) //返回给定地址引用一个数据值得第一个位置。如果给定地址没有引用其他地址，则返回BADADDR
long Dnext(long from, long current) //如果current已经在前一次调用Dfirst或Dnext时返回，则返回给定地址(from)向其引用一个数据值的下一个位置。如果没有其他交叉引用存在，则返回BADADDR
long XrefType() //返回一个常量，说明某个交叉引用查询函数（如Dfirst）返回的最后一个交叉引用的类型。对于数据交叉引用，这些常量包括dr_0（提供的偏移量）、dr_w（数据写入）和dr_R（数据读取）
long DfirstB(long to) //返回将给定地址作为数据引用的第一个位置。如果不存在引用给定地址的交叉引用，则返回BADADDR
long DnextB(long to, long current) //如果current已经在前一次调用DfirstB或DnextB时返回，则返回将给定地址（to）作为数据引用的下一个位置。如果没有其他对给定地址的交叉引用存在，则返回BADADDR
```

**数据库操纵函数**

```C
void MakeUnkn(long addr, long flags) //取消位于指定地址的项的定义。这里的标志指出是否也取消随后的想的定义，以及是否删除任何与取消定义的项有关的名称。
long MakeCode(long addr) //将位于指定地址的字节转换成一条指令
long MakeByte(long addr) //将位于指定地址的项目转换成一个数据字节。类似的函数还有MakeWord和MakeDword。
bool MakeComm(long addr, string comment) //在给定的地址处添加一条常规注释
bool MakeFunction(long begin, long end) //将有begin到end的指令转换成一个函数。如果end被指定为BADADDR（-1），IDA会尝试通过定位函数的返回指令，来自动确定该函数的结束地址
bool MakeStr(long begin, long end) //创建一个当前字符串(由GetStringType返回)类型的字符串，涵盖由begin到end-1之间的所有字节。如果end被指定为BADADDR，IDA会尝试自动确定字符串的结束地址
```

**数据库搜索函数**

```C
long FindCode(long addr, long flags) // 从给定的地址搜索一条指令
long FindDate(long addr, long flags) // 从给定的地址搜索一个数据项
long FindBinary(long addr, long flags, string binary) //从给定的地址搜索一个字节序列。字符串binary指定一个十六进制字节序列值。如果没有设置SEARCH_CASE，且一个字节值指定一个大写或小写ASCII字母，则搜索仍然会匹配对应的互补值。例如"41 42"将匹配"61 62"、"61 42"等
long FindText(long addr, long flags, long row, long column, string text) //在约定的地址，从给定行(row)的给定列搜索字符串text。注意，某个给定地址的反汇编文本可能会跨越几行，因此要指定从哪一行开始搜索
```

**反汇编行组件**

```C
string GetDisasm(long addr) //返回给定地址的反汇编文本。返回的文本包括任何注释，但不包括地址信息
string GetMnem(long addr) //返回位于给定地址的指令的助记符部分
string GetOpnd(long addr, long opnum) //返回给定地址的指定操作数的文本形式。IDA以0为其实编号，从左向右对操作数编号
long GetOpType(long addr, long opnum) //返回一个整数，指出给定地址的给定操作数的类型。
long GetOperandValue(long addr, long opnum) //返回与给定地址的给定操作数有关的整数值。返回值的性质取决于GetOpType指定的给定操作数的类型
string CommentEx(long addr, long type) //返回给定地址处的注释文本。如果type为0，则返回常规注释文本；如果type为1，则返回可重复注释的文本。如果给定地址没注释，则返回空字符串。
```

## 常用脚本

### dump 内存脚本

```C
static main(void)
{
	auto fp,startAddr,size;
	startAddr = 0; //这里填写需要dump的内存起始地址
	size = 0; //这里填写大小

	fp=fopen(“”,“wb”);//这里填写文件路径
	for( ; addr < startAddr + size; addr ++)
	fputc(Byte(addr),fp);
}
```

### SMC 脚本

```C
import idc

for i in range(234):
    idc.patch_byte(0x402219 + i, idc.get_db_byte(0x402219 + i) ^ 0x99)
```