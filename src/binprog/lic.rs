
use mylib::license::License;

fn main() {
    let lic = License {
        license_id: "abcdefg".to_string(),
        product: "yj_fgap_A".to_string(),
        customer: "客户A".to_string(),
        issue_date: "20191216".to_string(),
        expire_date: "20391216".to_string(),
    };

    match License::encode_license(&lic) {
        Ok(lic_encoded) => println!("{}", lic_encoded),
        Err(e) => eprintln!("error:{:?}", e),
    }
}

