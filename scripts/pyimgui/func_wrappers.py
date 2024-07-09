wrappers = {}


def gfunc_todo(func_name):
    wrappers[f"_GFUNC_:{func_name}"] = f'/* TODO:{func_name} */'


def gfunc_otsupport(func_name):
    wrappers[f"_GFUNC_:{func_name}"] = f'/* NotSupport:{func_name} */'


gfunc_todo("ImFont_CalcTextSizeA")
gfunc_todo("ImFontAtlas_GetTexDataAsAlpha8")
gfunc_todo("ImFontAtlas_GetTexDataAsRGBA32")
gfunc_todo("GetTexDataAsRGBA32")
gfunc_todo("igCombo_Str_arr")
gfunc_todo("igDebugNodeWindowsListByBeginStackParent")
gfunc_todo("igFindHoveredWindowEx")
gfunc_todo("igImFormatStringToTempBufferV")
gfunc_todo("igImTextStrFromUtf8")
gfunc_todo("igListBox_FnStrPtr")
gfunc_todo("igListBox_Str_arr")
gfunc_todo("igGetAllocatorFunctions")

gfunc_todo("ImGui_ImplDX12_RenderDrawData")
gfunc_todo("ImGui_ImplDX12_Init")
gfunc_todo("ImGui_ImplDX11_Init")
gfunc_todo("ImGui_ImplDX10_Init")
gfunc_todo("ImGui_ImplDX9_Init")

gfunc_otsupport('igTextV')


def _load_from_template():
    import pathlib
    with open(pathlib.Path(__file__).parent / 'func_wrappers.cpp') as f:
        s = f.read()
    # match /*START:funcname*/
    import re
    for match in re.finditer(r'/\*START:(.*)\*/(.*?)/\*END:\1\*/', s, re.DOTALL):
        wrappers[match.group(1)] = match.group(2).strip()


_load_from_template()

if __name__ == '__main__':
    for k, v in wrappers.items():
        print(f'{k}: {v}')
