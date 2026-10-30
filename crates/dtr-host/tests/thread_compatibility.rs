use dtr_host::{Coordinator, Input, Kernel, Output, Progress, Seal};
use dtr_wire::Result;
struct Pure;
impl Kernel for Pure {
    fn begin(&self, _: &[u8], _: &[Input], _: &Seal) -> Result<Vec<u8>> {
        unreachable!()
    }
    fn validate_cursor(&self, _: &[u8], _: &str) -> Result<()> {
        unreachable!()
    }
    fn step(&self, _: &[u8], _: usize) -> Result<(Vec<u8>, Progress)> {
        unreachable!()
    }
    fn result(&self, _: &[u8]) -> Result<Output> {
        unreachable!()
    }
}
#[test]
fn operation_proofs_preserve_original_native_auto_traits() {
    fn original_contract<T: Send + Sync + std::panic::RefUnwindSafe + std::panic::UnwindSafe>() {}
    original_contract::<Coordinator<Pure>>();
}
