// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use quick_xml::{
    Reader,
    events::{BytesStart, Event},
};
use serde::Deserialize;
use uuid::Uuid;

use crate::errors::ApiError;

pub(crate) const MAX_PORT_LIST_TEXT_BYTES: usize = 4096;
pub(crate) const MAX_PORT_LIST_CREATE_RANGES: usize = 1024;

// Derived from inherited gvmd make_port_ranges_openvas_default. Keep this list
// sparse; expanding to individual ports would change the port-list shape.
pub(crate) const OPENVAS_DEFAULT_TCP_RANGES: &[(i32, i32)] = &[
    (1, 5),
    (7, 7),
    (9, 9),
    (11, 11),
    (13, 13),
    (15, 15),
    (17, 25),
    (27, 27),
    (29, 29),
    (31, 31),
    (33, 33),
    (35, 35),
    (37, 39),
    (41, 59),
    (61, 224),
    (242, 248),
    (256, 268),
    (280, 287),
    (308, 322),
    (333, 333),
    (344, 700),
    (702, 702),
    (704, 707),
    (709, 711),
    (721, 721),
    (723, 723),
    (729, 731),
    (740, 742),
    (744, 744),
    (747, 754),
    (758, 765),
    (767, 767),
    (769, 777),
    (780, 783),
    (786, 787),
    (799, 801),
    (808, 808),
    (810, 810),
    (828, 829),
    (847, 848),
    (860, 860),
    (871, 871),
    (873, 873),
    (886, 888),
    (898, 898),
    (900, 904),
    (911, 913),
    (927, 927),
    (950, 950),
    (953, 953),
    (975, 975),
    (989, 1002),
    (1005, 1005),
    (1008, 1008),
    (1010, 1010),
    (1023, 1027),
    (1029, 1036),
    (1040, 1040),
    (1042, 1042),
    (1045, 1045),
    (1047, 1112),
    (1114, 1117),
    (1119, 1120),
    (1122, 1127),
    (1139, 1139),
    (1154, 1155),
    (1161, 1162),
    (1168, 1170),
    (1178, 1178),
    (1180, 1181),
    (1183, 1188),
    (1194, 1194),
    (1199, 1231),
    (1233, 1286),
    (1288, 1774),
    (1776, 2028),
    (2030, 2030),
    (2032, 2035),
    (2037, 2038),
    (2040, 2065),
    (2067, 2083),
    (2086, 2087),
    (2089, 2152),
    (2155, 2155),
    (2159, 2167),
    (2170, 2177),
    (2180, 2181),
    (2190, 2191),
    (2199, 2202),
    (2213, 2213),
    (2220, 2223),
    (2232, 2246),
    (2248, 2255),
    (2260, 2260),
    (2273, 2273),
    (2279, 2289),
    (2294, 2311),
    (2313, 2371),
    (2381, 2425),
    (2427, 2681),
    (2683, 2824),
    (2826, 2854),
    (2856, 2924),
    (2926, 3096),
    (3098, 3299),
    (3302, 3321),
    (3326, 3366),
    (3372, 3403),
    (3405, 3545),
    (3547, 3707),
    (3709, 3765),
    (3767, 3770),
    (3772, 3800),
    (3802, 3802),
    (3845, 3871),
    (3875, 3876),
    (3885, 3885),
    (3900, 3900),
    (3928, 3929),
    (3939, 3939),
    (3959, 3959),
    (3970, 3971),
    (3984, 3987),
    (3999, 4036),
    (4040, 4042),
    (4045, 4045),
    (4080, 4080),
    (4096, 4100),
    (4111, 4111),
    (4114, 4114),
    (4132, 4134),
    (4138, 4138),
    (4141, 4145),
    (4154, 4154),
    (4160, 4160),
    (4199, 4200),
    (4242, 4242),
    (4300, 4300),
    (4321, 4321),
    (4333, 4333),
    (4343, 4351),
    (4353, 4358),
    (4369, 4369),
    (4400, 4400),
    (4442, 4457),
    (4480, 4480),
    (4500, 4500),
    (4545, 4547),
    (4555, 4555),
    (4557, 4557),
    (4559, 4559),
    (4567, 4568),
    (4600, 4601),
    (4658, 4662),
    (4672, 4672),
    (4752, 4752),
    (4800, 4802),
    (4827, 4827),
    (4837, 4839),
    (4848, 4849),
    (4868, 4869),
    (4885, 4885),
    (4894, 4894),
    (4899, 4899),
    (4950, 4950),
    (4983, 4983),
    (4987, 4989),
    (4998, 4998),
    (5000, 5011),
    (5020, 5025),
    (5031, 5031),
    (5042, 5042),
    (5050, 5057),
    (5060, 5061),
    (5064, 5066),
    (5069, 5069),
    (5071, 5071),
    (5081, 5081),
    (5093, 5093),
    (5099, 5102),
    (5137, 5137),
    (5145, 5145),
    (5150, 5152),
    (5154, 5154),
    (5165, 5165),
    (5190, 5193),
    (5200, 5203),
    (5222, 5222),
    (5225, 5226),
    (5232, 5232),
    (5236, 5236),
    (5250, 5251),
    (5264, 5265),
    (5269, 5269),
    (5272, 5272),
    (5282, 5282),
    (5300, 5311),
    (5314, 5315),
    (5351, 5355),
    (5400, 5432),
    (5435, 5435),
    (5454, 5456),
    (5461, 5463),
    (5465, 5465),
    (5500, 5504),
    (5510, 5510),
    (5520, 5521),
    (5530, 5530),
    (5540, 5540),
    (5550, 5550),
    (5553, 5556),
    (5566, 5566),
    (5569, 5569),
    (5595, 5605),
    (5631, 5632),
    (5666, 5666),
    (5673, 5680),
    (5688, 5688),
    (5690, 5690),
    (5713, 5717),
    (5720, 5720),
    (5729, 5730),
    (5741, 5742),
    (5745, 5746),
    (5755, 5755),
    (5757, 5757),
    (5766, 5768),
    (5771, 5771),
    (5800, 5803),
    (5813, 5813),
    (5858, 5859),
    (5882, 5882),
    (5888, 5889),
    (5900, 5903),
    (5968, 5969),
    (5977, 5979),
    (5987, 5991),
    (5997, 6010),
    (6050, 6051),
    (6064, 6073),
    (6085, 6085),
    (6100, 6112),
    (6123, 6123),
    (6141, 6150),
    (6175, 6177),
    (6200, 6200),
    (6253, 6253),
    (6255, 6255),
    (6270, 6270),
    (6300, 6300),
    (6321, 6322),
    (6343, 6343),
    (6346, 6347),
    (6373, 6373),
    (6382, 6382),
    (6389, 6389),
    (6400, 6400),
    (6455, 6456),
    (6471, 6471),
    (6500, 6503),
    (6505, 6510),
    (6543, 6543),
    (6547, 6550),
    (6558, 6558),
    (6566, 6566),
    (6580, 6582),
    (6588, 6588),
    (6620, 6621),
    (6623, 6623),
    (6628, 6628),
    (6631, 6631),
    (6665, 6670),
    (6672, 6673),
    (6699, 6701),
    (6714, 6714),
    (6767, 6768),
    (6776, 6776),
    (6788, 6790),
    (6831, 6831),
    (6841, 6842),
    (6850, 6850),
    (6881, 6889),
    (6891, 6891),
    (6901, 6901),
    (6939, 6939),
    (6961, 6966),
    (6969, 6970),
    (6998, 7015),
    (7020, 7021),
    (7030, 7030),
    (7070, 7070),
    (7099, 7100),
    (7121, 7121),
    (7161, 7161),
    (7170, 7170),
    (7174, 7174),
    (7200, 7201),
    (7210, 7210),
    (7269, 7269),
    (7273, 7273),
    (7280, 7281),
    (7283, 7283),
    (7300, 7300),
    (7320, 7320),
    (7326, 7326),
    (7391, 7392),
    (7395, 7395),
    (7426, 7431),
    (7437, 7437),
    (7464, 7464),
    (7491, 7491),
    (7501, 7501),
    (7510, 7511),
    (7544, 7545),
    (7560, 7560),
    (7566, 7566),
    (7570, 7570),
    (7575, 7575),
    (7588, 7588),
    (7597, 7597),
    (7624, 7624),
    (7626, 7627),
    (7633, 7634),
    (7648, 7649),
    (7666, 7666),
    (7674, 7676),
    (7743, 7743),
    (7775, 7779),
    (7781, 7781),
    (7786, 7786),
    (7797, 7798),
    (7800, 7801),
    (7845, 7846),
    (7875, 7875),
    (7902, 7902),
    (7913, 7913),
    (7932, 7933),
    (7967, 7967),
    (7979, 7980),
    (7999, 8005),
    (8007, 8010),
    (8022, 8022),
    (8032, 8033),
    (8044, 8044),
    (8074, 8074),
    (8080, 8082),
    (8088, 8089),
    (8098, 8098),
    (8100, 8100),
    (8115, 8116),
    (8118, 8118),
    (8121, 8122),
    (8130, 8132),
    (8160, 8161),
    (8181, 8194),
    (8199, 8201),
    (8204, 8208),
    (8224, 8225),
    (8245, 8245),
    (8311, 8311),
    (8351, 8351),
    (8376, 8380),
    (8400, 8403),
    (8416, 8417),
    (8431, 8431),
    (8443, 8444),
    (8450, 8450),
    (8473, 8473),
    (8554, 8555),
    (8649, 8649),
    (8733, 8733),
    (8763, 8765),
    (8786, 8787),
    (8804, 8804),
    (8863, 8864),
    (8875, 8875),
    (8880, 8880),
    (8888, 8894),
    (8900, 8901),
    (8910, 8911),
    (8954, 8954),
    (8989, 8989),
    (8999, 9002),
    (9006, 9006),
    (9009, 9009),
    (9020, 9026),
    (9080, 9080),
    (9090, 9091),
    (9100, 9103),
    (9110, 9111),
    (9131, 9131),
    (9152, 9152),
    (9160, 9164),
    (9200, 9207),
    (9210, 9211),
    (9217, 9217),
    (9281, 9285),
    (9287, 9287),
    (9292, 9292),
    (9321, 9321),
    (9343, 9344),
    (9346, 9346),
    (9374, 9374),
    (9390, 9390),
    (9396, 9397),
    (9400, 9400),
    (9418, 9418),
    (9495, 9495),
    (9500, 9500),
    (9535, 9537),
    (9593, 9595),
    (9600, 9600),
    (9612, 9612),
    (9704, 9704),
    (9747, 9747),
    (9753, 9753),
    (9797, 9797),
    (9800, 9802),
    (9872, 9872),
    (9875, 9876),
    (9888, 9889),
    (9898, 9901),
    (9909, 9909),
    (9911, 9911),
    (9950, 9952),
    (9990, 10005),
    (10007, 10008),
    (10012, 10012),
    (10080, 10083),
    (10101, 10103),
    (10113, 10116),
    (10128, 10128),
    (10252, 10252),
    (10260, 10260),
    (10288, 10288),
    (10607, 10607),
    (10666, 10666),
    (10752, 10752),
    (10990, 10990),
    (11000, 11001),
    (11111, 11111),
    (11201, 11201),
    (11223, 11223),
    (11319, 11321),
    (11367, 11367),
    (11371, 11371),
    (11600, 11600),
    (11720, 11720),
    (11751, 11751),
    (11965, 11965),
    (11967, 11967),
    (11999, 12006),
    (12076, 12076),
    (12109, 12109),
    (12168, 12168),
    (12172, 12172),
    (12223, 12223),
    (12321, 12321),
    (12345, 12346),
    (12361, 12362),
    (12468, 12468),
    (12701, 12701),
    (12753, 12753),
    (13160, 13160),
    (13223, 13224),
    (13701, 13702),
    (13705, 13706),
    (13708, 13718),
    (13720, 13722),
    (13724, 13724),
    (13782, 13783),
    (13818, 13822),
    (14001, 14001),
    (14033, 14034),
    (14141, 14141),
    (14145, 14145),
    (14149, 14149),
    (14194, 14194),
    (14237, 14237),
    (14936, 14937),
    (15000, 15000),
    (15126, 15126),
    (15345, 15345),
    (15363, 15363),
    (16360, 16361),
    (16367, 16368),
    (16384, 16384),
    (16660, 16661),
    (16959, 16959),
    (16969, 16969),
    (16991, 16991),
    (17007, 17007),
    (17185, 17185),
    (17219, 17219),
    (17300, 17300),
    (17770, 17772),
    (18000, 18000),
    (18181, 18187),
    (18190, 18190),
    (18241, 18241),
    (18463, 18463),
    (18769, 18769),
    (18888, 18888),
    (19191, 19191),
    (19194, 19194),
    (19283, 19283),
    (19315, 19315),
    (19398, 19398),
    (19410, 19412),
    (19540, 19541),
    (19638, 19638),
    (19726, 19726),
    (20000, 20001),
    (20005, 20005),
    (20011, 20012),
    (20034, 20034),
    (20200, 20200),
    (20202, 20203),
    (20222, 20222),
    (20670, 20670),
    (20999, 21000),
    (21490, 21490),
    (21544, 21544),
    (21590, 21590),
    (21800, 21800),
    (21845, 21849),
    (22000, 22001),
    (22222, 22222),
    (22273, 22273),
    (22289, 22289),
    (22305, 22305),
    (22321, 22321),
    (22370, 22370),
    (22555, 22555),
    (22800, 22800),
    (22951, 22951),
    (23456, 23456),
    (24000, 24006),
    (24242, 24242),
    (24249, 24249),
    (24345, 24347),
    (24386, 24386),
    (24554, 24554),
    (24677, 24678),
    (24922, 24922),
    (25000, 25009),
    (25378, 25378),
    (25544, 25544),
    (25793, 25793),
    (25867, 25867),
    (25901, 25901),
    (25903, 25903),
    (26000, 26000),
    (26208, 26208),
    (26260, 26264),
    (27000, 27010),
    (27345, 27345),
    (27374, 27374),
    (27504, 27504),
    (27665, 27665),
    (27999, 27999),
    (28001, 28001),
    (29559, 29559),
    (29891, 29891),
    (30001, 30002),
    (30100, 30102),
    (30303, 30303),
    (30999, 30999),
    (31337, 31337),
    (31339, 31339),
    (31416, 31416),
    (31457, 31457),
    (31554, 31554),
    (31556, 31556),
    (31620, 31620),
    (31765, 31765),
    (31785, 31787),
    (32261, 32261),
    (32666, 32666),
    (32768, 32780),
    (32786, 32787),
    (32896, 32896),
    (33270, 33270),
    (33331, 33331),
    (33434, 33434),
    (33911, 33911),
    (34249, 34249),
    (34324, 34324),
    (34952, 34952),
    (36865, 36865),
    (37475, 37475),
    (37651, 37651),
    (38037, 38037),
    (38201, 38201),
    (38292, 38293),
    (39681, 39681),
    (40412, 40412),
    (40841, 40843),
    (41111, 41111),
    (41508, 41508),
    (41794, 41795),
    (42508, 42510),
    (43118, 43118),
    (43188, 43190),
    (44321, 44322),
    (44333, 44334),
    (44442, 44443),
    (44818, 44818),
    (45000, 45000),
    (45054, 45054),
    (45678, 45678),
    (45966, 45966),
    (47000, 47000),
    (47557, 47557),
    (47624, 47624),
    (47806, 47806),
    (47808, 47808),
    (47891, 47891),
    (48000, 48003),
    (48556, 48556),
    (49400, 49400),
    (50000, 50004),
    (50505, 50505),
    (50776, 50776),
    (51210, 51210),
    (53001, 53001),
    (54320, 54321),
    (57341, 57341),
    (59595, 59595),
    (60177, 60177),
    (60179, 60179),
    (61439, 61441),
    (61446, 61446),
    (65000, 65000),
    (65301, 65301),
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PortListPatchRequest {
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) comment: Option<String>,
    #[serde(default)]
    pub(crate) port_ranges: Option<Vec<PortListCreateRangeRequest>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PortListCreateRequest {
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) comment: Option<String>,
    pub(crate) port_ranges: Vec<PortListCreateRangeRequest>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PortListImportRequest {
    pub(crate) xml_file: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PortListCloneRequest {
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) comment: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PortListCreateRangeRequest {
    pub(crate) protocol: String,
    pub(crate) start: i32,
    pub(crate) end: i32,
    #[serde(default)]
    pub(crate) comment: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedPortListPatch {
    pub(crate) name: Option<String>,
    pub(crate) comment: Option<String>,
    pub(crate) port_ranges: Option<Vec<ValidatedPortListCreateRange>>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedPortListCreate {
    pub(crate) imported_id: Option<String>,
    pub(crate) deduplicate_name: bool,
    pub(crate) name: String,
    pub(crate) comment: String,
    pub(crate) port_ranges: Vec<ValidatedPortListCreateRange>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedPortListClone {
    pub(crate) name: Option<String>,
    pub(crate) comment: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ValidatedPortListCreateRange {
    pub(crate) protocol_id: i32,
    pub(crate) start: i32,
    pub(crate) end: i32,
    pub(crate) comment: String,
}

pub(crate) fn validate_port_list_create_request(
    request: PortListCreateRequest,
) -> Result<ValidatedPortListCreate, ApiError> {
    let name = normalize_required_port_list_text(request.name, "name")?;
    let comment =
        normalize_optional_port_list_text(request.comment, "comment")?.unwrap_or_default();
    let port_ranges = validate_port_list_ranges(request.port_ranges, "port list create request")?;
    Ok(ValidatedPortListCreate {
        imported_id: None,
        deduplicate_name: false,
        name,
        comment,
        port_ranges,
    })
}

pub(crate) fn validate_port_list_import_request(
    request: PortListImportRequest,
) -> Result<ValidatedPortListCreate, ApiError> {
    if request.xml_file.len() > 1_048_576 {
        return Err(ApiError::BadRequest(
            "port list import XML must be at most 1048576 bytes".to_string(),
        ));
    }
    parse_port_list_import_xml(&request.xml_file)
}

fn parse_port_list_import_xml(xml: &str) -> Result<ValidatedPortListCreate, ApiError> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut in_response = false;
    let mut in_port_list = false;
    let mut in_range = false;
    let mut current = String::new();
    let mut imported_id: Option<String> = None;
    let mut name: Option<String> = None;
    let mut comment: Option<String> = None;
    let mut range_protocol: Option<String> = None;
    let mut range_start: Option<String> = None;
    let mut range_end: Option<String> = None;
    let mut range_comment: Option<String> = None;
    let mut ranges = Vec::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(event)) => {
                let local = xml_local_name(event.name().as_ref()).to_vec();
                match local.as_slice() {
                    b"get_port_lists_response" => in_response = true,
                    b"port_list" if in_response && !in_port_list => {
                        in_port_list = true;
                        imported_id = xml_attr_value(&event, b"id")?;
                    }
                    b"port_range" if in_port_list => {
                        in_range = true;
                        range_protocol = None;
                        range_start = None;
                        range_end = None;
                        range_comment = None;
                    }
                    _ => {}
                }
                current = String::from_utf8_lossy(&local).into_owned();
            }
            Ok(Event::Text(event)) => {
                if in_port_list {
                    let text = event
                        .decode()
                        .map(|value| value.into_owned())
                        .unwrap_or_default();
                    match (in_range, current.as_str()) {
                        (false, "name") => name = Some(text),
                        (false, "comment") => comment = Some(text),
                        (true, "type") => range_protocol = Some(text),
                        (true, "start") => range_start = Some(text),
                        (true, "end") => range_end = Some(text),
                        (true, "comment") => range_comment = Some(text),
                        _ => {}
                    }
                }
            }
            Ok(Event::CData(event)) => {
                if in_port_list {
                    let text = event
                        .decode()
                        .map(|value| value.into_owned())
                        .unwrap_or_default();
                    match (in_range, current.as_str()) {
                        (false, "name") => name = Some(text),
                        (false, "comment") => comment = Some(text),
                        (true, "type") => range_protocol = Some(text),
                        (true, "start") => range_start = Some(text),
                        (true, "end") => range_end = Some(text),
                        (true, "comment") => range_comment = Some(text),
                        _ => {}
                    }
                }
            }
            Ok(Event::End(event)) => match xml_local_name(event.name().as_ref()) {
                b"port_range" if in_range => {
                    ranges.push(PortListCreateRangeRequest {
                        protocol: range_protocol.take().unwrap_or_default(),
                        start: parse_import_port(range_start.take(), "port range start")?,
                        end: parse_import_port(range_end.take(), "port range end")?,
                        comment: range_comment.take(),
                    });
                    in_range = false;
                    current.clear();
                }
                b"port_list" if in_port_list => break,
                b"get_port_lists_response" => in_response = false,
                _ => current.clear(),
            },
            Ok(Event::Eof) => break,
            Err(error) => {
                tracing::warn!(%error, "port list import XML parse failed");
                return Err(ApiError::BadRequest(
                    "port list import XML is invalid".to_string(),
                ));
            }
            _ => {}
        }
    }

    let imported_id = imported_id.ok_or_else(|| {
        ApiError::BadRequest("port list import XML must include a port_list id".to_string())
    })?;
    let imported_id = Uuid::parse_str(&imported_id)
        .map_err(|_| ApiError::BadRequest("port list import id must be a UUID".to_string()))?
        .to_string();
    let name =
        normalize_required_port_list_text(name.unwrap_or_default(), "port list import name")?;
    let ranges = if ranges.is_empty() {
        openvas_default_port_ranges()
    } else {
        ranges
    };
    let port_ranges = validate_port_list_ranges(ranges, "port list import XML")?;
    Ok(ValidatedPortListCreate {
        imported_id: Some(imported_id),
        deduplicate_name: true,
        name,
        comment: normalize_optional_port_list_text(comment, "port list import comment")?
            .unwrap_or_default(),
        port_ranges,
    })
}

fn openvas_default_port_ranges() -> Vec<PortListCreateRangeRequest> {
    OPENVAS_DEFAULT_TCP_RANGES
        .iter()
        .map(|(start, end)| PortListCreateRangeRequest {
            protocol: "tcp".to_string(),
            start: *start,
            end: *end,
            comment: None,
        })
        .collect()
}

fn parse_import_port(value: Option<String>, field_name: &str) -> Result<i32, ApiError> {
    value
        .unwrap_or_default()
        .trim()
        .parse::<i32>()
        .map_err(|_| ApiError::BadRequest(format!("{field_name} must be an integer")))
}

fn xml_attr_value(event: &BytesStart<'_>, name: &[u8]) -> Result<Option<String>, ApiError> {
    for attr in event.attributes() {
        let attr =
            attr.map_err(|_| ApiError::BadRequest("port list import XML is invalid".to_string()))?;
        if xml_local_name(attr.key.as_ref()) == name {
            return Ok(Some(
                String::from_utf8_lossy(attr.value.as_ref()).into_owned(),
            ));
        }
    }
    Ok(None)
}

fn xml_local_name(name: &[u8]) -> &[u8] {
    name.rsplit(|byte| *byte == b':').next().unwrap_or(name)
}

fn validate_port_list_create_range(
    range: PortListCreateRangeRequest,
) -> Result<ValidatedPortListCreateRange, ApiError> {
    let protocol_id = match range.protocol.trim().to_ascii_lowercase().as_str() {
        "tcp" => 0,
        "udp" => 1,
        _ => {
            return Err(ApiError::BadRequest(
                "port range protocol must be tcp or udp".to_string(),
            ));
        }
    };
    if !(1..=65535).contains(&range.start) || !(1..=65535).contains(&range.end) {
        return Err(ApiError::BadRequest(
            "port range start and end must be between 1 and 65535".to_string(),
        ));
    }
    if range.end < range.start {
        return Err(ApiError::BadRequest(
            "port range end must be greater than or equal to start".to_string(),
        ));
    }
    Ok(ValidatedPortListCreateRange {
        protocol_id,
        start: range.start,
        end: range.end,
        comment: normalize_optional_port_list_text(range.comment, "port range comment")?
            .unwrap_or_default(),
    })
}

pub(crate) fn validate_port_list_create_range_request(
    request: PortListCreateRangeRequest,
) -> Result<ValidatedPortListCreateRange, ApiError> {
    validate_port_list_create_range(request)
}

pub(crate) fn validate_port_list_patch_request(
    request: PortListPatchRequest,
) -> Result<ValidatedPortListPatch, ApiError> {
    let port_ranges = request
        .port_ranges
        .map(|ranges| validate_port_list_ranges(ranges, "port list patch request"))
        .transpose()?;
    let validated = ValidatedPortListPatch {
        name: normalize_optional_required_port_list_text(request.name, "name")?,
        comment: normalize_optional_port_list_text(request.comment, "comment")?,
        port_ranges,
    };
    if validated.name.is_none() && validated.comment.is_none() && validated.port_ranges.is_none() {
        return Err(ApiError::BadRequest(
            "port list patch request must include at least one field".to_string(),
        ));
    }
    Ok(validated)
}

pub(crate) fn validate_port_list_clone_request(
    request: PortListCloneRequest,
) -> Result<ValidatedPortListClone, ApiError> {
    Ok(ValidatedPortListClone {
        name: normalize_optional_required_port_list_text(request.name, "name")?,
        comment: normalize_optional_port_list_text(request.comment, "comment")?,
    })
}

fn validate_port_list_ranges(
    ranges: Vec<PortListCreateRangeRequest>,
    request_name: &str,
) -> Result<Vec<ValidatedPortListCreateRange>, ApiError> {
    if ranges.is_empty() {
        return Err(ApiError::BadRequest(format!(
            "{request_name} must include at least one port range"
        )));
    }
    if ranges.len() > MAX_PORT_LIST_CREATE_RANGES {
        return Err(ApiError::BadRequest(format!(
            "{request_name} may include at most {MAX_PORT_LIST_CREATE_RANGES} ranges"
        )));
    }
    let mut ranges = ranges
        .into_iter()
        .map(validate_port_list_create_range)
        .collect::<Result<Vec<_>, _>>()?;
    ranges.sort_by_key(|range| (range.protocol_id, range.start, range.end));
    for pair in ranges.windows(2) {
        let previous = &pair[0];
        let current = &pair[1];
        if previous.protocol_id == current.protocol_id && previous.end >= current.start {
            return Err(ApiError::BadRequest(format!(
                "{request_name} contains overlapping ranges"
            )));
        }
    }
    Ok(ranges)
}

fn normalize_optional_required_port_list_text(
    value: Option<String>,
    field_name: &str,
) -> Result<Option<String>, ApiError> {
    value
        .map(|value| normalize_required_port_list_text(value, field_name))
        .transpose()
}

fn normalize_required_port_list_text(value: String, field_name: &str) -> Result<String, ApiError> {
    let value = normalize_port_list_text_value(value, field_name)?;
    if value.is_empty() {
        Err(ApiError::BadRequest(format!("{field_name} is required")))
    } else {
        Ok(value)
    }
}

fn normalize_optional_port_list_text(
    value: Option<String>,
    field_name: &str,
) -> Result<Option<String>, ApiError> {
    value
        .map(|value| normalize_port_list_text_value(value, field_name))
        .transpose()
}

fn normalize_port_list_text_value(value: String, field_name: &str) -> Result<String, ApiError> {
    let value = value.trim().to_string();
    if value.len() > MAX_PORT_LIST_TEXT_BYTES || value.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(format!(
            "{field_name} must be printable text up to {MAX_PORT_LIST_TEXT_BYTES} bytes"
        )));
    }
    Ok(value)
}
