// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Non-bitset libc++ 19 address-sort specialization. Source: LLVM 19.1.7
// __algorithm/{sort,sift_down,push_heap,pop_heap,make_heap,sort_heap,partial_sort}.h.
// Kept independent of the platform's std::sort: the original comparator has
// a nontransitive three-second tolerance, so algorithm/order are observable.
// Original instruction reference: NETWORKING section 10.1. See LLVM-LICENSE.txt.
#pragma once
#include <algorithm>
#include <cassert>
#include <iterator>
#include <utility>
#define _LIBCPP_ASSERT_VALID_ELEMENT_ACCESS(c,m) assert(c)
#define _LIBCPP_ASSERT_INTERNAL(c,m) assert(c)
#define _LIBCPP_ASSERT_PEDANTIC(c,m) assert(c)
namespace nsl_address_sort {
using std::iterator_traits;
struct _ClassicAlgPolicy {};
template<class C> using __comp_ref_type = C&;
template<class P> struct _IterOps {
    template<class I> static auto&& __iter_move(I i) { return std::move(*i); }
    template<class I> static void iter_swap(I a, I b) { std::iter_swap(a,b); }
    template<class I> static I next(I, I last) { return last; }
};
template<class... A> void __debug_randomize_range(A&&...) {}
template<class P, class... A> void __debug_randomize_range(A&&...) {}
template<class... A> void __check_strict_weak_ordering_sorted(A&&...) {}
template <class _AlgPolicy, class _Compare, class _ForwardIterator>
  unsigned
__sort3(_ForwardIterator __x, _ForwardIterator __y, _ForwardIterator __z, _Compare __c) {
  using _Ops = _IterOps<_AlgPolicy>;

  unsigned __r = 0;
  if (!__c(*__y, *__x)) // if x <= y
  {
    if (!__c(*__z, *__y))      // if y <= z
      return __r;              // x <= y && y <= z
                               // x <= y && y > z
    _Ops::iter_swap(__y, __z); // x <= z && y < z
    __r = 1;
    if (__c(*__y, *__x)) // if x > y
    {
      _Ops::iter_swap(__x, __y); // x < y && y <= z
      __r = 2;
    }
    return __r; // x <= y && y < z
  }
  if (__c(*__z, *__y)) // x > y, if y > z
  {
    _Ops::iter_swap(__x, __z); // x < y && y < z
    __r = 1;
    return __r;
  }
  _Ops::iter_swap(__x, __y); // x > y && y <= z
  __r = 1;                   // x < y && x <= z
  if (__c(*__z, *__y))       // if y > z
  {
    _Ops::iter_swap(__y, __z); // x <= y && y < z
    __r = 2;
  }
  return __r;
}

template <class _AlgPolicy, class _Compare, class _ForwardIterator>
 void
__sort4(_ForwardIterator __x1, _ForwardIterator __x2, _ForwardIterator __x3, _ForwardIterator __x4, _Compare __c) {
  using _Ops = _IterOps<_AlgPolicy>;
  nsl_address_sort::__sort3<_AlgPolicy, _Compare>(__x1, __x2, __x3, __c);
  if (__c(*__x4, *__x3)) {
    _Ops::iter_swap(__x3, __x4);
    if (__c(*__x3, *__x2)) {
      _Ops::iter_swap(__x2, __x3);
      if (__c(*__x2, *__x1)) {
        _Ops::iter_swap(__x1, __x2);
      }
    }
  }
}

template <class _AlgPolicy, class _Comp, class _ForwardIterator>
 void
__sort5(_ForwardIterator __x1,
        _ForwardIterator __x2,
        _ForwardIterator __x3,
        _ForwardIterator __x4,
        _ForwardIterator __x5,
        _Comp __comp) {
  using _Ops = _IterOps<_AlgPolicy>;

  nsl_address_sort::__sort4<_AlgPolicy, _Comp>(__x1, __x2, __x3, __x4, __comp);
  if (__comp(*__x5, *__x4)) {
    _Ops::iter_swap(__x4, __x5);
    if (__comp(*__x4, *__x3)) {
      _Ops::iter_swap(__x3, __x4);
      if (__comp(*__x3, *__x2)) {
        _Ops::iter_swap(__x2, __x3);
        if (__comp(*__x2, *__x1)) {
          _Ops::iter_swap(__x1, __x2);
        }
      }
    }
  }
}

template<class P, class C, class I> void __sort3_maybe_branchless(I x0, I x1, I x2, C c) { __sort3<P,C>(x0, x1, x2,c); }

template<class P, class C, class I> void __sort4_maybe_branchless(I x0, I x1, I x2, I x3, C c) { __sort4<P,C>(x0, x1, x2, x3,c); }

template<class P, class C, class I> void __sort5_maybe_branchless(I x0, I x1, I x2, I x3, I x4, C c) { __sort5<P,C>(x0, x1, x2, x3, x4,c); }

template <class _AlgPolicy, class _Compare, class _BidirectionalIterator>
 void
__insertion_sort(_BidirectionalIterator __first, _BidirectionalIterator __last, _Compare __comp) {
  using _Ops = _IterOps<_AlgPolicy>;

  typedef typename iterator_traits<_BidirectionalIterator>::value_type value_type;
  if (__first == __last)
    return;
  _BidirectionalIterator __i = __first;
  for (++__i; __i != __last; ++__i) {
    _BidirectionalIterator __j = __i;
    --__j;
    if (__comp(*__i, *__j)) {
      value_type __t(_Ops::__iter_move(__i));
      _BidirectionalIterator __k = __j;
      __j                        = __i;
      do {
        *__j = _Ops::__iter_move(__k);
        __j  = __k;
      } while (__j != __first && __comp(__t, *--__k));
      *__j = std::move(__t);
    }
  }
}

template <class _AlgPolicy, class _Compare, class _RandomAccessIterator>
 void
__insertion_sort_unguarded(_RandomAccessIterator const __first, _RandomAccessIterator __last, _Compare __comp) {
  using _Ops = _IterOps<_AlgPolicy>;
  typedef typename iterator_traits<_RandomAccessIterator>::difference_type difference_type;
  typedef typename iterator_traits<_RandomAccessIterator>::value_type value_type;
  if (__first == __last)
    return;
  const _RandomAccessIterator __leftmost = __first - difference_type(1);
  (void)__leftmost; // can be unused when assertions are disabled
  for (_RandomAccessIterator __i = __first + difference_type(1); __i != __last; ++__i) {
    _RandomAccessIterator __j = __i - difference_type(1);
    if (__comp(*__i, *__j)) {
      value_type __t(_Ops::__iter_move(__i));
      _RandomAccessIterator __k = __j;
      __j                       = __i;
      do {
        *__j = _Ops::__iter_move(__k);
        __j  = __k;
        _LIBCPP_ASSERT_VALID_ELEMENT_ACCESS(
            __k != __leftmost,
            "Would read out of bounds, does your comparator satisfy the strict-weak ordering requirement?");
      } while (__comp(__t, *--__k)); // No need for bounds check due to the assumption stated above.
      *__j = std::move(__t);
    }
  }
}

template <class _AlgPolicy, class _Comp, class _RandomAccessIterator>
 bool
__insertion_sort_incomplete(_RandomAccessIterator __first, _RandomAccessIterator __last, _Comp __comp) {
  using _Ops = _IterOps<_AlgPolicy>;

  typedef typename iterator_traits<_RandomAccessIterator>::difference_type difference_type;
  switch (__last - __first) {
  case 0:
  case 1:
    return true;
  case 2:
    if (__comp(*--__last, *__first))
      _Ops::iter_swap(__first, __last);
    return true;
  case 3:
    nsl_address_sort::__sort3_maybe_branchless<_AlgPolicy, _Comp>(__first, __first + difference_type(1), --__last, __comp);
    return true;
  case 4:
    nsl_address_sort::__sort4_maybe_branchless<_AlgPolicy, _Comp>(
        __first, __first + difference_type(1), __first + difference_type(2), --__last, __comp);
    return true;
  case 5:
    nsl_address_sort::__sort5_maybe_branchless<_AlgPolicy, _Comp>(
        __first,
        __first + difference_type(1),
        __first + difference_type(2),
        __first + difference_type(3),
        --__last,
        __comp);
    return true;
  }
  typedef typename iterator_traits<_RandomAccessIterator>::value_type value_type;
  _RandomAccessIterator __j = __first + difference_type(2);
  nsl_address_sort::__sort3_maybe_branchless<_AlgPolicy, _Comp>(__first, __first + difference_type(1), __j, __comp);
  const unsigned __limit = 8;
  unsigned __count       = 0;
  for (_RandomAccessIterator __i = __j + difference_type(1); __i != __last; ++__i) {
    if (__comp(*__i, *__j)) {
      value_type __t(_Ops::__iter_move(__i));
      _RandomAccessIterator __k = __j;
      __j                       = __i;
      do {
        *__j = _Ops::__iter_move(__k);
        __j  = __k;
      } while (__j != __first && __comp(__t, *--__k));
      *__j = std::move(__t);
      if (++__count == __limit)
        return ++__i == __last;
    }
    __j = __i;
  }
  return true;
}

template <class _AlgPolicy, class _RandomAccessIterator, class _Compare>
 std::pair<_RandomAccessIterator, bool>
__partition_with_equals_on_right(_RandomAccessIterator __first, _RandomAccessIterator __last, _Compare __comp) {
  using _Ops = _IterOps<_AlgPolicy>;
  typedef typename iterator_traits<_RandomAccessIterator>::difference_type difference_type;
  typedef typename std::iterator_traits<_RandomAccessIterator>::value_type value_type;
  _LIBCPP_ASSERT_INTERNAL(__last - __first >= difference_type(3), "");
  const _RandomAccessIterator __begin = __first; // used for bounds checking, those are not moved around
  const _RandomAccessIterator __end   = __last;
  (void)__end; //
  value_type __pivot(_Ops::__iter_move(__first));
  // Find the first element greater or equal to the pivot.  It will be always
  // guarded because __introsort will do the median-of-three before calling
  // this.
  do {
    ++__first;
    _LIBCPP_ASSERT_VALID_ELEMENT_ACCESS(
        __first != __end,
        "Would read out of bounds, does your comparator satisfy the strict-weak ordering requirement?");
  } while (__comp(*__first, __pivot));

  // Find the last element less than the pivot.
  if (__begin == __first - difference_type(1)) {
    while (__first < __last && !__comp(*--__last, __pivot))
      ;
  } else {
    // Guarded.
    do {
      _LIBCPP_ASSERT_VALID_ELEMENT_ACCESS(
          __last != __begin,
          "Would read out of bounds, does your comparator satisfy the strict-weak ordering requirement?");
      --__last;
    } while (!__comp(*__last, __pivot));
  }

  // If the first element greater than or equal to the pivot is at or after the
  // last element less than the pivot, then we have covered the entire range
  // without swapping elements.  This implies the range is already partitioned.
  bool __already_partitioned = __first >= __last;
  // Go through the remaining elements.  Swap pairs of elements (one to the
  // right of the pivot and the other to left of the pivot) that are not on the
  // correct side of the pivot.
  while (__first < __last) {
    _Ops::iter_swap(__first, __last);
    do {
      ++__first;
      _LIBCPP_ASSERT_VALID_ELEMENT_ACCESS(
          __first != __end,
          "Would read out of bounds, does your comparator satisfy the strict-weak ordering requirement?");
    } while (__comp(*__first, __pivot));
    do {
      _LIBCPP_ASSERT_VALID_ELEMENT_ACCESS(
          __last != __begin,
          "Would read out of bounds, does your comparator satisfy the strict-weak ordering requirement?");
      --__last;
    } while (!__comp(*__last, __pivot));
  }
  // Move the pivot to its correct position.
  _RandomAccessIterator __pivot_pos = __first - difference_type(1);
  if (__begin != __pivot_pos) {
    *__begin = _Ops::__iter_move(__pivot_pos);
  }
  *__pivot_pos = std::move(__pivot);
  return std::make_pair(__pivot_pos, __already_partitioned);
}

template <class _AlgPolicy, class _RandomAccessIterator, class _Compare>
 _RandomAccessIterator
__partition_with_equals_on_left(_RandomAccessIterator __first, _RandomAccessIterator __last, _Compare __comp) {
  using _Ops = _IterOps<_AlgPolicy>;
  typedef typename iterator_traits<_RandomAccessIterator>::difference_type difference_type;
  typedef typename std::iterator_traits<_RandomAccessIterator>::value_type value_type;
  const _RandomAccessIterator __begin = __first; // used for bounds checking, those are not moved around
  const _RandomAccessIterator __end   = __last;
  (void)__end; //
  value_type __pivot(_Ops::__iter_move(__first));
  if (__comp(__pivot, *(__last - difference_type(1)))) {
    // Guarded.
    do {
      ++__first;
      _LIBCPP_ASSERT_VALID_ELEMENT_ACCESS(
          __first != __end,
          "Would read out of bounds, does your comparator satisfy the strict-weak ordering requirement?");
    } while (!__comp(__pivot, *__first));
  } else {
    while (++__first < __last && !__comp(__pivot, *__first)) {
    }
  }

  if (__first < __last) {
    // It will be always guarded because __introsort will do the
    // median-of-three before calling this.
    do {
      _LIBCPP_ASSERT_VALID_ELEMENT_ACCESS(
          __last != __begin,
          "Would read out of bounds, does your comparator satisfy the strict-weak ordering requirement?");
      --__last;
    } while (__comp(__pivot, *__last));
  }
  while (__first < __last) {
    _Ops::iter_swap(__first, __last);
    do {
      ++__first;
      _LIBCPP_ASSERT_VALID_ELEMENT_ACCESS(
          __first != __end,
          "Would read out of bounds, does your comparator satisfy the strict-weak ordering requirement?");
    } while (!__comp(__pivot, *__first));
    do {
      _LIBCPP_ASSERT_VALID_ELEMENT_ACCESS(
          __last != __begin,
          "Would read out of bounds, does your comparator satisfy the strict-weak ordering requirement?");
      --__last;
    } while (__comp(__pivot, *__last));
  }
  _RandomAccessIterator __pivot_pos = __first - difference_type(1);
  if (__begin != __pivot_pos) {
    *__begin = _Ops::__iter_move(__pivot_pos);
  }
  *__pivot_pos = std::move(__pivot);
  return __first;
}

template <class _AlgPolicy, class _Compare, class _RandomAccessIterator>
  void
__sift_up(_RandomAccessIterator __first,
          _RandomAccessIterator __last,
          _Compare&& __comp,
          typename iterator_traits<_RandomAccessIterator>::difference_type __len) {
  using value_type = typename iterator_traits<_RandomAccessIterator>::value_type;

  if (__len > 1) {
    __len                       = (__len - 2) / 2;
    _RandomAccessIterator __ptr = __first + __len;

    if (__comp(*__ptr, *--__last)) {
      value_type __t(_IterOps<_AlgPolicy>::__iter_move(__last));
      do {
        *__last = _IterOps<_AlgPolicy>::__iter_move(__ptr);
        __last  = __ptr;
        if (__len == 0)
          break;
        __len = (__len - 1) / 2;
        __ptr = __first + __len;
      } while (__comp(*__ptr, __t));

      *__last = std::move(__t);
    }
  }
}

template <class _AlgPolicy, class _Compare, class _RandomAccessIterator>
  void
__sift_down(_RandomAccessIterator __first,
            _Compare&& __comp,
            typename iterator_traits<_RandomAccessIterator>::difference_type __len,
            _RandomAccessIterator __start) {
  using _Ops = _IterOps<_AlgPolicy>;

  typedef typename iterator_traits<_RandomAccessIterator>::difference_type difference_type;
  typedef typename iterator_traits<_RandomAccessIterator>::value_type value_type;
  // left-child of __start is at 2 * __start + 1
  // right-child of __start is at 2 * __start + 2
  difference_type __child = __start - __first;

  if (__len < 2 || (__len - 2) / 2 < __child)
    return;

  __child                         = 2 * __child + 1;
  _RandomAccessIterator __child_i = __first + __child;

  if ((__child + 1) < __len && __comp(*__child_i, *(__child_i + difference_type(1)))) {
    // right-child exists and is greater than left-child
    ++__child_i;
    ++__child;
  }

  // check if we are in heap-order
  if (__comp(*__child_i, *__start))
    // we are, __start is larger than its largest child
    return;

  value_type __top(_Ops::__iter_move(__start));
  do {
    // we are not in heap-order, swap the parent with its largest child
    *__start = _Ops::__iter_move(__child_i);
    __start  = __child_i;

    if ((__len - 2) / 2 < __child)
      break;

    // recompute the child based off of the updated parent
    __child   = 2 * __child + 1;
    __child_i = __first + __child;

    if ((__child + 1) < __len && __comp(*__child_i, *(__child_i + difference_type(1)))) {
      // right-child exists and is greater than left-child
      ++__child_i;
      ++__child;
    }

    // check if we are in heap-order
  } while (!__comp(*__child_i, __top));
  *__start = std::move(__top);
}

template <class _AlgPolicy, class _Compare, class _RandomAccessIterator>
  _RandomAccessIterator __floyd_sift_down(
    _RandomAccessIterator __first,
    _Compare&& __comp,
    typename iterator_traits<_RandomAccessIterator>::difference_type __len) {
  using difference_type = typename iterator_traits<_RandomAccessIterator>::difference_type;
  _LIBCPP_ASSERT_INTERNAL(__len >= 2, "shouldn't be called unless __len >= 2");

  _RandomAccessIterator __hole    = __first;
  _RandomAccessIterator __child_i = __first;
  difference_type __child         = 0;

  while (true) {
    __child_i += difference_type(__child + 1);
    __child = 2 * __child + 1;

    if ((__child + 1) < __len && __comp(*__child_i, *(__child_i + difference_type(1)))) {
      // right-child exists and is greater than left-child
      ++__child_i;
      ++__child;
    }

    // swap __hole with its largest child
    *__hole = _IterOps<_AlgPolicy>::__iter_move(__child_i);
    __hole  = __child_i;

    // if __hole is now a leaf, we're done
    if (__child > (__len - 2) / 2)
      return __hole;
  }
}

template <class _AlgPolicy, class _Compare, class _RandomAccessIterator>
inline   void
__pop_heap(_RandomAccessIterator __first,
           _RandomAccessIterator __last,
           _Compare& __comp,
           typename iterator_traits<_RandomAccessIterator>::difference_type __len) {
  // Calling `pop_heap` on an empty range is undefined behavior, but in practice it will be a no-op.
  _LIBCPP_ASSERT_PEDANTIC(__len > 0, "The heap given to pop_heap must be non-empty");

  __comp_ref_type<_Compare> __comp_ref = __comp;

  using value_type = typename iterator_traits<_RandomAccessIterator>::value_type;
  if (__len > 1) {
    value_type __top             = _IterOps<_AlgPolicy>::__iter_move(__first); // create a hole at __first
    _RandomAccessIterator __hole = nsl_address_sort::__floyd_sift_down<_AlgPolicy>(__first, __comp_ref, __len);
    --__last;

    if (__hole == __last) {
      *__hole = std::move(__top);
    } else {
      *__hole = _IterOps<_AlgPolicy>::__iter_move(__last);
      ++__hole;
      *__last = std::move(__top);
      nsl_address_sort::__sift_up<_AlgPolicy>(__first, __hole, __comp_ref, __hole - __first);
    }
  }
}

template <class _AlgPolicy, class _Compare, class _RandomAccessIterator>
inline   void
__make_heap(_RandomAccessIterator __first, _RandomAccessIterator __last, _Compare&& __comp) {
  __comp_ref_type<_Compare> __comp_ref = __comp;

  using difference_type = typename iterator_traits<_RandomAccessIterator>::difference_type;
  difference_type __n   = __last - __first;
  if (__n > 1) {
    // start from the first parent, there is no need to consider children
    for (difference_type __start = (__n - 2) / 2; __start >= 0; --__start) {
      nsl_address_sort::__sift_down<_AlgPolicy>(__first, __comp_ref, __n, __first + __start);
    }
  }
}

template <class _AlgPolicy, class _Compare, class _RandomAccessIterator>
inline   void
__sort_heap(_RandomAccessIterator __first, _RandomAccessIterator __last, _Compare&& __comp) {
  _RandomAccessIterator __saved_last   = __last;
  __comp_ref_type<_Compare> __comp_ref = __comp;

  using difference_type = typename iterator_traits<_RandomAccessIterator>::difference_type;
  for (difference_type __n = __last - __first; __n > 1; --__last, (void)--__n)
    nsl_address_sort::__pop_heap<_AlgPolicy>(__first, __last, __comp_ref, __n);
  nsl_address_sort::__check_strict_weak_ordering_sorted(__first, __saved_last, __comp_ref);
}

template <class _AlgPolicy, class _Compare, class _RandomAccessIterator, class _Sentinel>
  _RandomAccessIterator __partial_sort_impl(
    _RandomAccessIterator __first, _RandomAccessIterator __middle, _Sentinel __last, _Compare&& __comp) {
  if (__first == __middle) {
    return _IterOps<_AlgPolicy>::next(__middle, __last);
  }

  nsl_address_sort::__make_heap<_AlgPolicy>(__first, __middle, __comp);

  typename iterator_traits<_RandomAccessIterator>::difference_type __len = __middle - __first;
  _RandomAccessIterator __i                                              = __middle;
  for (; __i != __last; ++__i) {
    if (__comp(*__i, *__first)) {
      _IterOps<_AlgPolicy>::iter_swap(__i, __first);
      nsl_address_sort::__sift_down<_AlgPolicy>(__first, __comp, __len, __first);
    }
  }
  nsl_address_sort::__sort_heap<_AlgPolicy>(std::move(__first), std::move(__middle), __comp);

  return __i;
}

template <class _AlgPolicy, class _Compare, class _RandomAccessIterator, class _Sentinel>
  _RandomAccessIterator
__partial_sort(_RandomAccessIterator __first, _RandomAccessIterator __middle, _Sentinel __last, _Compare& __comp) {
  if (__first == __middle)
    return _IterOps<_AlgPolicy>::next(__middle, __last);

  nsl_address_sort::__debug_randomize_range<_AlgPolicy>(__first, __last);

  auto __last_iter =
      nsl_address_sort::__partial_sort_impl<_AlgPolicy>(__first, __middle, __last, static_cast<__comp_ref_type<_Compare> >(__comp));

  nsl_address_sort::__debug_randomize_range<_AlgPolicy>(__middle, __last);

  return __last_iter;
}

template <class _AlgPolicy, class _Compare, class _RandomAccessIterator, bool _UseBitSetPartition>
void __introsort(_RandomAccessIterator __first,
                 _RandomAccessIterator __last,
                 _Compare __comp,
                 typename iterator_traits<_RandomAccessIterator>::difference_type __depth,
                 bool __leftmost = true) {
  using _Ops = _IterOps<_AlgPolicy>;
  typedef typename iterator_traits<_RandomAccessIterator>::difference_type difference_type;
  using _Comp_ref = __comp_ref_type<_Compare>;
  // Upper bound for using insertion sort for sorting.
   difference_type __limit = 24;
  // Lower bound for using Tuckey's ninther technique for median computation.
   difference_type __ninther_threshold = 128;
  while (true) {
    difference_type __len = __last - __first;
    switch (__len) {
    case 0:
    case 1:
      return;
    case 2:
      if (__comp(*--__last, *__first))
        _Ops::iter_swap(__first, __last);
      return;
    case 3:
      nsl_address_sort::__sort3_maybe_branchless<_AlgPolicy, _Compare>(__first, __first + difference_type(1), --__last, __comp);
      return;
    case 4:
      nsl_address_sort::__sort4_maybe_branchless<_AlgPolicy, _Compare>(
          __first, __first + difference_type(1), __first + difference_type(2), --__last, __comp);
      return;
    case 5:
      nsl_address_sort::__sort5_maybe_branchless<_AlgPolicy, _Compare>(
          __first,
          __first + difference_type(1),
          __first + difference_type(2),
          __first + difference_type(3),
          --__last,
          __comp);
      return;
    }
    // Use insertion sort if the length of the range is below the specified limit.
    if (__len < __limit) {
      if (__leftmost) {
        nsl_address_sort::__insertion_sort<_AlgPolicy, _Compare>(__first, __last, __comp);
      } else {
        nsl_address_sort::__insertion_sort_unguarded<_AlgPolicy, _Compare>(__first, __last, __comp);
      }
      return;
    }
    if (__depth == 0) {
      // Fallback to heap sort as Introsort suggests.
      nsl_address_sort::__partial_sort<_AlgPolicy, _Compare>(__first, __last, __last, __comp);
      return;
    }
    --__depth;
    {
      difference_type __half_len = __len / 2;
      // Use Tuckey's ninther technique or median of 3 for pivot selection
      // depending on the length of the range being sorted.
      if (__len > __ninther_threshold) {
        nsl_address_sort::__sort3<_AlgPolicy, _Compare>(__first, __first + __half_len, __last - difference_type(1), __comp);
        nsl_address_sort::__sort3<_AlgPolicy, _Compare>(
            __first + difference_type(1), __first + (__half_len - 1), __last - difference_type(2), __comp);
        nsl_address_sort::__sort3<_AlgPolicy, _Compare>(
            __first + difference_type(2), __first + (__half_len + 1), __last - difference_type(3), __comp);
        nsl_address_sort::__sort3<_AlgPolicy, _Compare>(
            __first + (__half_len - 1), __first + __half_len, __first + (__half_len + 1), __comp);
        _Ops::iter_swap(__first, __first + __half_len);
      } else {
        nsl_address_sort::__sort3<_AlgPolicy, _Compare>(__first + __half_len, __first, __last - difference_type(1), __comp);
      }
    }
    // The elements to the left of the current iterator range are already
    // sorted.  If the current iterator range to be sorted is not the
    // leftmost part of the entire iterator range and the pivot is same as
    // the highest element in the range to the left, then we know that all
    // the elements in the range [first, pivot] would be equal to the pivot,
    // assuming the equal elements are put on the left side when
    // partitioned.  This also means that we do not need to sort the left
    // side of the partition.
    if (!__leftmost && !__comp(*(__first - difference_type(1)), *__first)) {
      __first = nsl_address_sort::__partition_with_equals_on_left<_AlgPolicy, _RandomAccessIterator, _Comp_ref>(
          __first, __last, _Comp_ref(__comp));
      continue;
    }
    // Use bitset partition only if asked for.
    auto __ret = nsl_address_sort::__partition_with_equals_on_right<_AlgPolicy, _RandomAccessIterator, _Compare>(__first, __last, __comp);
    _RandomAccessIterator __i = __ret.first;
    // [__first, __i) < *__i and *__i <= [__i+1, __last)
    // If we were given a perfect partition, see if insertion sort is quick...
    if (__ret.second) {
      bool __fs = nsl_address_sort::__insertion_sort_incomplete<_AlgPolicy, _Compare>(__first, __i, __comp);
      if (nsl_address_sort::__insertion_sort_incomplete<_AlgPolicy, _Compare>(__i + difference_type(1), __last, __comp)) {
        if (__fs)
          return;
        __last = __i;
        continue;
      } else {
        if (__fs) {
          __first = ++__i;
          continue;
        }
      }
    }
    // Sort the left partiton recursively and the right partition with tail recursion elimination.
    nsl_address_sort::__introsort<_AlgPolicy, _Compare, _RandomAccessIterator, _UseBitSetPartition>(
        __first, __i, __comp, __depth, __leftmost);
    __leftmost = false;
    __first    = ++__i;
  }
}
}
#undef _LIBCPP_ASSERT_VALID_ELEMENT_ACCESS
#undef _LIBCPP_ASSERT_INTERNAL
#undef _LIBCPP_ASSERT_PEDANTIC
