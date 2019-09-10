pub trait Key {
    fn new(parties: Vec<String>, share_count: usize, threshold: usize) -> Self;    
    fn from_backup(input: String) -> Self;
    fn get_backup(&self) -> String;
    fn to_string(&self) -> String;
}

pub trait Sign {
    fn new<T>(key: &T, message: &str, parties: Vec<String>, threshold: usize) -> Self where T: Key + serde::ser::Serialize;
    fn verify(input: String) -> String;
    fn to_string(&self) -> String;
}