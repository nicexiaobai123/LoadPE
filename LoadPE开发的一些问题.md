# 0、CListCtrl 中得到选中行号

```c++
//	得到选中进程的PID
int sel_row = -1;
sel_row = m_list_process.GetNextItem(-1, LVNI_SELECTED);
//	改行1列的数据
int pid = _ttoi(m_list_process.GetItemText(sel_row, 1).GetString());
if (sel_row == -1) return;
```

# 1、点击按钮弹出系统的文件浏览

MFC的一个类：CFileDialog；头文件：#include <afxdlgs.h>

详细代码：

```c++
// PE编辑器按钮
void CMain::OnBnClickedButtonPeedit()
{
	// 过滤器
	TCHAR szFilter[] = 
	TEXT("可执行文件(*.exe;*sys;*dll)|*.exe;*.sys;*.dll|所有文件(*.*)|*.*||");
	CFileDialog fileBrowser(TRUE, TEXT(".exe"), NULL, 0, szFilter, this);
    // 当是选择为"确认" 时
	if (fileBrowser.DoModal() == IDOK) {
		CString str = fileBrowser.GetPathName();
		MessageBox(str);
	}
}
```

# 2、对话框的文件拖拽获取文件功能

- 首先得先打开对话框允许拖拽文件的属性；设置为true

![image-20220920212330432](LoadPE开发日记.assets/image-20220920212330432.png)

- 对消息WM_DROPFILES进行捕获，设置对应函数

![image-20220920212434367](LoadPE开发日记.assets/image-20220920212434367.png)

- 捕获函数，获得文件路径

```C++
// 文件拖拽触发
void CMain::OnDropFiles(HDROP hDropInfo)
{
	TCHAR szFilename[256] = {};
	DragQueryFile(hDropInfo, 0, szFilename, 254);
	MessageBox(szFilename);
	CDialogEx::OnDropFiles(hDropInfo);
}
```

# 3、64位与32位分开编译

为什么要分开编译：

1、远程注入：创建远程线程时指定的LoadLibrary函数回调；如果当前应用程序是64位程序，LoadLibrary的地址就是64位dll的LoadLibrary地址，是64位地址；被注入进程是32位则不能找到指定LoadLibrary地址，无法加载dll，32位程序远程线程注入也是同理；32位还是64位只会加载一套系统dll，一个是wow64的，一个system32；

2、PE加载器，区分32位和64位然后去分别解析；

3、模块遍历也按64位和32位区分开来

# 4、设置CListCtrl点击其他控件后还有阴影

就是设置CListCtrl始终显示选定内容

![image-20220921110941984](LoadPE开发日记.assets/image-20220921110941984.png)



# 5、加壳功能说明

加壳使用的是以前写好的一个类，这个class使用了大量的string类型，而string类型不支持wchar_t* 类型字符串；

所以想要保存加壳功能正确编译，需要将项目字符集整个改为多字节字符

![image-20220922153405951](LoadPE开发日记.assets/image-20220922153405951.png)

加壳的壳dll：此dll需要用release版本，debug版本的有很多检查，release版本设置MT模式

![image-20220922172622652](LoadPE开发日记.assets/image-20220922172622652.png)

注意事项：

壳子程序中修复导入表：可能有些程序的OriginalFirstThunk可能被复制成0，所以用FirstThunk遍历修复

目前加壳还只支持32位应用程序

原因有二：

1、64位PE结构有些不同，导入表重定位表的位置不一样  2、壳dll只搞了个32位的

# 6、判断是否是64当前编译环境是否是64位

```c++
#if defined(_WIN64)
	this->m_imagebase.Format(TEXT("%p"), (LPVOID)pe.poption_header->ImageBase);
#else
	if (pe.is_32PE()) {
		this->m_imagebase.Format(TEXT("%p"), (LPVOID)pe.poption_header->ImageBase);
	}
	else {
		this->m_imagebase.Format(TEXT("%08x%08x"), pe.poption_header->ImageBase, pe.poption_header->BaseOfData);
	}
#endif
```

# 7、编辑框初始化出来后默认自带选中状态

去掉选中状态，在OnInit中设置；最后返回false

```C++
//	编辑框去掉选中状态  init最后返回false
CEdit* pEdit = (CEdit*)GetDlgItem(IDC_EDIT0);
pEdit->SetFocus();
return false
```

# 8、类型要泛型

在写代码时，需要保证代码的通用性，既x86和x64下都能够使用，使用类型别写死了

比如不要写DWORD这种，应该改写成DWORD_PTR，除非API已经确定这个参数是DWORD类型或者自己已经完全决定了

RVA 、FOA那些不用泛型，这些始终都是四字节；**主要是注意地址**

注意！！！！，一些东西用宏最好用宏，别特么写死的

# 9、C++中判断内存是否有效

```C++
//	使用ReadProcessMemory间接判断地址是否无效
DWORD judge = 0;
if (!ReadProcessMemory(GetCurrentProcess(), (LPVOID)pFirstThunk, &judge, 4, NULL))
{
    AfxMessageBox("访问内存发生错误");
    EndDialog(0);
    return;
}
```

