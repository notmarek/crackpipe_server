pub use macros_impl::Checksum;

pub trait Checksum {
    fn hashable_string(&self, salt: &str) -> String;
    fn get_sig(&self, salt: &str) -> String;
}