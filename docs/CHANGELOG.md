# Changelog
## 20/08/2026
### Added 
- Added `debug/` to save macsec_manager  debug log
### Changed
- Remove `configs/wpa_supplicant.conf`. All config will be in `configs/macsec_def.conf`
- Changed `macsec_def.conf`: Adding wpa_supplicant config and macsec policy config
- Changed `common.sh`:
* Adding validate_config(), generate_wpa_config()
- Changed `start.sh`:
* In step 2, remove copy wpa_supplicant.conf logic. Using generate_wpa_config() from common.sh

