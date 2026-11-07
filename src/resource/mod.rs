pub mod budget;
pub mod manager;
pub mod retention;

#[cfg(test)]
#[path = "spec_resource_tests.rs"]
mod spec_resource_tests;

#[cfg(test)]
#[path = "spec_lease4_tests.rs"]
mod spec_lease4_tests;
