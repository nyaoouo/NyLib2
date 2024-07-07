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

wrappers['igText'] = '.def("Text", [](const char* s) { return igText(s);}, py::arg("s")="")'
wrappers['igCheckbox'] = ('.def("Checkbox", [](const char* label,bool v) {'
                          'auto changed = igCheckbox(label, &v);'
                          'return py::make_tuple(changed,v);'
                          '}, py::arg("label")="", py::arg("v")=false)')
wrappers['igShowAboutWindow'] = ('.def("ShowAboutWindow", [](bool is_open) {'
                                 'igShowAboutWindow(&is_open);'
                                 'return is_open;'
                                 '}, py::arg("is_open")=true)')
wrappers['igShowDebugLogWindow'] = ('.def("ShowDebugLogWindow", [](bool is_open) {'
                                    'igShowDebugLogWindow(&is_open);'
                                    'return is_open;'
                                    '}, py::arg("is_open")=true)')
wrappers['igShowDemoWindow'] = ('.def("ShowDemoWindow", [](bool is_open) {'
                                'igShowDemoWindow(&is_open);'
                                'return is_open;'
                                '}, py::arg("is_open")=true)')
wrappers['igShowIDStackToolWindow'] = ('.def("ShowIDStackToolWindow", [](bool is_open) {'
                                       'igShowIDStackToolWindow(&is_open);'
                                       'return is_open;'
                                       '}, py::arg("is_open")=true)')
wrappers['igShowMetricsWindow'] = ('.def("ShowMetricsWindow", [](bool is_open) {'
                                   'igShowMetricsWindow(&is_open);'
                                   'return is_open;'
                                   '}, py::arg("is_open")=true)')
wrappers['igBegin'] = ('.def("Begin", [](const char* name,bool open,ImGuiWindowFlags flags) {'
                       'auto is_collapsed = igBegin(name, &open, flags);'
                       'return py::make_tuple(is_collapsed,open);'
                       '}, py::arg("name")="", py::arg("open")=true, py::arg("flags")=0)')
wrappers['igCombo_Str'] = ('.def("Combo", [](const char* label,int current_item,const char* items_separated_by_zeros,int popup_max_height_in_items) {'
                           'auto changed = igCombo_Str(label, &current_item, items_separated_by_zeros, popup_max_height_in_items);'
                           'return py::make_tuple(changed,current_item);'
                           '}, py::arg("label")="", py::arg("current_item")=0, py::arg("items_separated_by_zeros")=nullptr, py::arg("popup_max_height_in_items")=0);')
wrappers['igGetWindowPos'] = ('.def("GetWindowPos", []() {'
                              'ImVec2 pos = {};'
                              'igGetWindowPos(&pos);'
                              'return pos;'
                              '}, py::return_value_policy::move)')
wrappers['igGetWindowSize'] = ('.def("GetWindowSize", []() {'
                               'ImVec2 size = {};'
                               'igGetWindowSize(&size);'
                               'return size;'
                               '}, py::return_value_policy::move)')
wrappers['igColorEdit3'] = (
    '.def("ColorEdit3", [](const char* label,ImVec4& color,ImGuiColorEditFlags flags) {'
    'auto changed = igColorEdit3(label, (float*)&color, flags);'
    'return py::make_tuple(changed,color);'
    '},py::arg("label"),py::arg("color"),py::arg("flags")=0, py::return_value_policy::move)'
    '.def("ColorEdit3", [](const char* label,ImColor color,ImGuiColorEditFlags flags) {'
    'auto changed = igColorEdit3(label, (float*)&color, flags);'
    'return py::make_tuple(changed,color);'
    '},py::arg("label"),py::arg("color"),py::arg("flags")=0, py::return_value_policy::move)'
)
wrappers['igColorEdit4'] = (
    '.def("ColorEdit4", [](const char* label,ImVec4& color,ImGuiColorEditFlags flags) {'
    'auto changed = igColorEdit4(label, (float*)&color, flags);'
    'return py::make_tuple(changed,color);'
    '},py::arg("label"),py::arg("color"),py::arg("flags")=0, py::return_value_policy::move)'
    '.def("ColorEdit4", [](const char* label,ImColor color,ImGuiColorEditFlags flags) {'
    'auto changed = igColorEdit4(label, (float*)&color, flags);'
    'return py::make_tuple(changed,color);'
    '},py::arg("label"),py::arg("color"),py::arg("flags")=0, py::return_value_policy::move)'
)
wrappers['igGetIO'] = (
    '.def("GetIO", &igGetIO, py::return_value_policy::reference)'
)
