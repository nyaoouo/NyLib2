#include <iostream>
#include <tuple>
#include <cstdarg>

template<typename Func, typename Tuple, std::size_t... I>
decltype(auto) call_with_tuple_impl(Func&& func, Tuple&& t, std::index_sequence<I...>)
{
    return std::forward<Func>(func)(std::get<I>(std::forward<Tuple>(t))...);
}

template<typename Func, typename Tuple>
decltype(auto) call_with_tuple(Func&& func, Tuple&& t)
{
    constexpr auto size = std::tuple_size<typename std::decay<Tuple>::type>::value;
    return call_with_tuple_impl(std::forward<Func>(func), std::forward<Tuple>(t),
                                std::make_index_sequence<size>{});
}
