
/// Macro for localization - simplified version
/// In a full implementation, this would look up translations
macro_rules! fl {
    ($key:expr) => {
        $key
    };
    ($key:expr, $($name:ident = $value:expr),*) => {
        {
            let mut result = String::from($key);
            $(
                let placeholder = format!("{{{}}}", stringify!($name));
                result = result.replace(&placeholder, &$value.to_string());
            )*
            result
        }
    };
}

pub(crate) use fl;