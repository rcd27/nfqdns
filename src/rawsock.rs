use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, RawFd};

/// AF_PACKET raw socket для перехвата и инъекции пакетов на L2.
pub struct RawSocket {
    fd: RawFd,
    ifindex: i32,
}

impl RawSocket {
    /// Открывает AF_PACKET socket на указанном интерфейсе.
    /// ETH_P_IP (0x0800) — ловим только IPv4 пакеты.
    pub fn bind(iface: &str) -> io::Result<Self> {
        let ifindex = get_ifindex(iface)?;

        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW,
                (libc::ETH_P_ALL as u16).to_be() as i32,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // Bind к конкретному интерфейсу
        let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
        addr.sll_ifindex = ifindex;

        let ret = unsafe {
            libc::bind(
                fd,
                &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as u32,
            )
        };
        if ret < 0 {
            unsafe { libc::close(fd) };
            return Err(io::Error::last_os_error());
        }

        Ok(RawSocket { fd, ifindex })
    }

    /// Читает один Ethernet frame. Возвращает (данные, source sockaddr_ll).
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, libc::sockaddr_ll)> {
        let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        let mut addr_len = std::mem::size_of::<libc::sockaddr_ll>() as u32;

        let n = unsafe {
            libc::recvfrom(
                self.fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
                &mut addr as *mut libc::sockaddr_ll as *mut libc::sockaddr,
                &mut addr_len,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((n as usize, addr))
    }

    /// Отправляет Ethernet frame на тот же интерфейс.
    /// `dst_mac` — MAC адрес получателя (из оригинального пакета).
    pub fn send(&self, data: &[u8], dst_mac: &[u8; 6]) -> io::Result<usize> {
        let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_protocol = (libc::ETH_P_IP as u16).to_be();
        addr.sll_ifindex = self.ifindex;
        addr.sll_halen = 6;
        addr.sll_addr[..6].copy_from_slice(dst_mac);

        let n = unsafe {
            libc::sendto(
                self.fd,
                data.as_ptr() as *const libc::c_void,
                data.len(),
                0,
                &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as u32,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }
}

impl AsRawFd for RawSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for RawSocket {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

fn get_ifindex(iface: &str) -> io::Result<i32> {
    let name = CString::new(iface).map_err(|_| io::Error::other("invalid interface name"))?;
    let idx = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if idx == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(idx as i32)
}
