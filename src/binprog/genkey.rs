
use rand::Rng;
use base64;

fn main()
{
    let key:[u8;16] = rand::thread_rng().gen();
    let iv:[u8;16] = rand::thread_rng().gen();
    println!("key=\"{}\"", base64::encode(&key));
    println!(" iv=\"{}\"", base64::encode(&iv));
}

