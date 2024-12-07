pub mod forward;
pub mod geoip;
pub mod stats;

enum MemcachedStatus {
    _Unknown,
    IpBlocked,
    _IpWhiteList,
}