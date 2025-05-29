#[macro_export]
macro_rules! dictionary {
    () => {
        $crate::object::Dictionary::new()
    };
    ($($key:expr => $value:expr),+ $(,)?) => {{
        let mut dict = $crate::object::Dictionary::new();
        $(
            dict.set($key, $value);
        )+
        dict
    }};
}