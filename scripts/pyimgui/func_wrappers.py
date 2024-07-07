wrappers = {}


def todo(func_name):
    wrappers[func_name] = f'/* TODO:{func_name} */'


def notsupport(func_name):
    wrappers[func_name] = f'/* NotSupport:{func_name} */'


todo("ImFont_CalcTextSizeA")
todo("ImFontAtlas_GetTexDataAsAlpha8")
todo("ImFontAtlas_GetTexDataAsRGBA32")
todo("GetTexDataAsRGBA32")
todo("igCombo_Str_arr")
todo("igDebugNodeWindowsListByBeginStackParent")
todo("igFindHoveredWindowEx")
todo("igImFormatStringToTempBufferV")
todo("igImTextStrFromUtf8")
todo("igListBox_FnStrPtr")
todo("igListBox_Str_arr")
todo("igGetAllocatorFunctions")

todo("ImGui_ImplDX12_RenderDrawData")
todo("ImGui_ImplDX12_Init")
todo("ImGui_ImplDX11_Init")
todo("ImGui_ImplDX10_Init")
todo("ImGui_ImplDX9_Init")

notsupport('igTextV')


def _load_from_template():
    import pathlib
    with open(pathlib.Path(__file__).parent / 'func_wrappers.cpp') as f:
        s = f.read()
    # match /*START:funcname*/
    import re
    for match in re.finditer(r'/\*START:(\w+)\*/(.*?)/\*END:\1\*/', s, re.DOTALL):
        wrappers[match.group(1)] = match.group(2).strip()


_load_from_template()

if __name__ == '__main__':
    for k, v in wrappers.items():
        print(f'{k}: {v}')
