use byteorder::ByteOrder;

use std::mem::size_of;

macro_rules! fn_vec {
    ($name:ident, $orig:ident, $num:ty) => {
        fn $name(n: $num) -> Vec<u8> {
            let mut vec = Vec::with_capacity(size_of::<$num>());
            vec.resize(size_of::<$num>(), 0);
            Self::$orig(&mut vec, n);
            vec
        }
    };
}

pub trait ByteOrderExt: ByteOrder {
    fn_vec!(u16_vec, write_u16, u16);
    fn_vec!(u32_vec, write_u32, u32);
    fn_vec!(u64_vec, write_u64, u64);
    fn_vec!(i16_vec, write_i16, i16);
    fn_vec!(i32_vec, write_i32, i32);
    fn_vec!(i64_vec, write_i64, i64);
}

impl<T: ByteOrder> ByteOrderExt for T {}
