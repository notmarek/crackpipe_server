#[macro_use]
extern crate rocket;

#[get("/")]
fn hello() -> &'static str {
    "Hello, world!"
}

#[launch]
fn rocket() -> _ {
    let mut builder = rocket::build()
        .configure(rocket::Config::figment().merge(("port", 80)))
        .mount("/", routes![hello]);

    builder = akebi::setup(builder);
    builder = generic_keyauth::setup(builder);
    builder = korepi::setup(builder);
    builder = crackpipe::setup(builder);
    builder
}
