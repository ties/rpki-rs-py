use std::{fmt::Display, str::FromStr};

#[derive(Debug, PartialEq, Eq)]
pub enum RpkiObjectType {
    Aspa,
    Cert,
    Crl,
    Manifest,
    Roa,
    Tak,
}

impl RpkiObjectType {
    pub const VARIANTS: [RpkiObjectType; 6] = [
        RpkiObjectType::Aspa,
        RpkiObjectType::Cert,
        RpkiObjectType::Crl,
        RpkiObjectType::Manifest,
        RpkiObjectType::Roa,
        RpkiObjectType::Tak,
    ];
}

impl Display for RpkiObjectType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpkiObjectType::Aspa => write!(f, "asa"),
            RpkiObjectType::Cert => write!(f, "cer"),
            RpkiObjectType::Crl => write!(f, "crl"),
            RpkiObjectType::Manifest => write!(f, "mft"),
            RpkiObjectType::Roa => write!(f, "roa"),
            RpkiObjectType::Tak => write!(f, "tak"),
        }
    }
}

impl FromStr for RpkiObjectType {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<RpkiObjectType, &'static str> {
        let ext = std::path::Path::new(s)
            .extension()
            .and_then(|os| os.to_str())
            .unwrap_or("")
            .to_lowercase();

        match ext.as_str() {
            "asa" => Ok(RpkiObjectType::Aspa),
            "cer" => Ok(RpkiObjectType::Cert),
            "crl" => Ok(RpkiObjectType::Crl),
            "mft" => Ok(RpkiObjectType::Manifest),
            "roa" => Ok(RpkiObjectType::Roa),
            "tak" => Ok(RpkiObjectType::Tak),
            _ => Err("invalid extension"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rpki_object_type_from_url() {
        let test_cases = vec![
            (
                "rsync://rpki.arin.net/repository/arin-rpki-ta/5e4a23ea/af328904-d764-39ee-a186-96c8bedcee04.roa",
                Ok(RpkiObjectType::Roa),
            ),
            (
                "rsync://rpki.arin.net/repository/arin-rpki-ta/delta-xxx.mft",
                Ok(RpkiObjectType::Manifest),
            ),
            (
                "rsync://rpki.arin.net/repository/arin-rpki-ta/a234649d-ab49-458b-a5e3-7765fe7a066c.crl",
                Ok(RpkiObjectType::Crl),
            ),
            (
                "rsync://rpki.arin.net/abc/044c251c-ba49.roa",
                Ok(RpkiObjectType::Roa),
            ),
            (
                "https://example.com/some/path/file.cer",
                Ok(RpkiObjectType::Cert),
            ),
            (
                "https://example.com/unknown.extension",
                Err("invalid extension"),
            ),
        ];

        for (uri, expected) in test_cases {
            assert_eq!(RpkiObjectType::from_str(uri), expected, "URI: {uri}");
        }
    }
}
