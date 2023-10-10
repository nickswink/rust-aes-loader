use std::ptr;
use winapi::shared::windef::{HWND, POINT};
use winapi::um::winuser::{GetCursorPos, GetForegroundWindow, GetWindowRect};
use std::thread;
use std::time::Duration;

// Function to wait until the mouse moves
pub fn wait_for_mouse_movement() {
    let last_cursor_pos = get_cursor_pos();
    loop {
        let cursor_pos = get_cursor_pos();
        if cursor_pos.x != last_cursor_pos.x || cursor_pos.y != last_cursor_pos.y {
            break;
        }

        // Sleep for a short duration before checking again
        thread::sleep(Duration::from_millis(100));
    }
}

// Helper function to retrieve the current cursor position
fn get_cursor_pos() -> POINT {
    let mut cursor_pos = POINT { x: 0, y: 0 };
    unsafe {
        GetCursorPos(&mut cursor_pos);
    }
    cursor_pos
}



