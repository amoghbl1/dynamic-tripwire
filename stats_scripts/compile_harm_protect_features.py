#!/usr/bin/env python3
import json
HARM_PROTECT_DATA = "combined_stats/harm_protect.json"
FEATURE_COLORS = "FEATURE_COLOR_MAP"

RESULT_FILES = [
    "combined_stats/pii_leak_harm.json", # PII LEAKING RESULTS
    "combined_stats/https_harm_protect.json", # HTTPS Verification Failure apps
    "combined_stats/history_leak_harm.json", # Browsing history leakers
]

MAKE_BINARY = [
    "combined_stats/html_harm_protect.json", # HTML DIFF RESULTS
    "combined_stats/requests_harm_protect.json", # Request blocking missed
]

MANUALLY_ADDED_RESULTS = {
    #"jp.co.fenrir.android.sleipnir_test-AB22C99280384B7FAA07123EA482384CFE59BA36661E033B4FF7D8A4C904F1AE": {
    #        "Inject fenrir": -5
    #    }
}


BOTTOM_KEY = "_bottom"

# Ordering irrelevant
COLORS = [
    ["Script blocking", "#0000FF"], ["Script blocking_bottom", "#000000"],
    # ["Inject fenrir", "#FF0000"], ["Inject fenrir_bottom", "#000000"],
    ["IMEI", "#FF4444"], ["IMEI_bottom", "#000000"],
    ["Device MAC", "#FF4444"], ["Device MAC_bottom", "#000000"],
    ["WiFi MAC", "#FF4444"], ["WiFi MAC_bottom", "#000000"],
    ["WiFi Name", "#FF4444"], ["WiFi Name_bottom", "#000000"],
    ["Android ID", "#FF4444"], ["Android ID_bottom", "#000000"],
    ["Installed Packages", "#FF4444"], ["Installed Packages_bottom", "#000000"],
    ["Advertisement ID", "#FF8888"], ["Advertisement ID_bottom", "#000000"],
    ["Device IP", "#FF8888"], ["Device IP_bottom", "#000000"],
    ["Location", "#FFCCCC"], ["Location_bottom", "#000000"],
    ["Resettable ID", "#FF8888"], ["Resettable ID_bottom", "#000000"],
    ["Non-resettable ID", "#FF4444"], ["Non-resettable ID", "#000000"],
    # ["OS Info", "#FFCCCC"], ["OS Info_bottom", "#FFCCCC"],
]

# Ordering irrelevant
GROUPED_COLORS = [
    ["Script blocking", "#00BFFF"], ["Script blocking_bottom", "#000000"],
    ["HTTPS default", "#00FF00"], ["HTTPS default_bottom", "#000000"],
#    ["Unnecessary blocking", "#0000FF"], ["Unnecessary blocking_bottom", "#000000"],
#    ["Non-resettable ID", "#FF4444"], ["Non-resettable ID_bottom", "#000000"],
#    ["Resettable ID", "#FF8888"], ["Resettable ID_bottom", "#000000"],
#    ["Installed Packages", "#FF4444"], ["Installed Packages_bottom", "#000000"],
#    ["Location", "#FFCCCC"], ["Location_bottom", "#000000"],
    ["TLS problem", "#006400"], ["TLS problem_bottom", "#000000"],
    ["History Leak", "#FF8C00"], ["History Leak_bottom", "#000000"],
    ["PII Exposure", "#FF0000"], ["PII Exposure_bottom", "#000000"],
    ["Request blocking missed", "#6495ED"], ["Request blocking missed_bottom", "#000000"]
]

################################################
## ORDERING VERY IMPORTANT, ORDERS BARS       ##
## ALSO ONLY WRITES DATA IN THIS LIST TO PLOT ##
################################################
GOOD_FEATURES = [
    "HTTPS default",
    "Script blocking"
]

################################################
## ORDERING VERY IMPORTANT, ORDERS BARS       ##
## ALSO ONLY WRITES DATA IN THIS LIST TO PLOT ##
################################################
GROUPED_GOOD_FEATURES = [
    "HTTPS default",
    "Script blocking"
]

################################################
## ORDERING VERY IMPORTANT, ORDERS BARS       ##
## ALSO ONLY WRITES DATA IN THIS LIST TO PLOT ##
################################################
BAD_FEATURES = [
    "Inject fenrir",
    "IMEI",
    "Device MAC",
    "WiFi MAC",
    "WiFi Name",
    "Android ID",
    "Installed Packages",
    "Advertisement ID",
    "Device IP",
    "Location",
    # "OS Info",
]

################################################
## ORDERING VERY IMPORTANT, ORDERS BARS       ##
## ALSO ONLY WRITES DATA IN THIS LIST TO PLOT ##
################################################
GROUPED_BAD_FEATURES = [
#    "Unnecessary blocking",
    "Request blocking missed",
    "TLS problem",
    "History Leak",
    "PII Exposure",
#    "Non-resettable ID",
#    "Resettable ID",
#    "Installed Packages",
#    "Location",
]

GROUPED = True

def main():
    combined_harm_protect = {}
    # Set what features we wish to plot
    if GROUPED:
        features = set(GROUPED_GOOD_FEATURES + GROUPED_BAD_FEATURES)
    else:
        features = set(GOOD_FEATURES + BAD_FEATURES)
    for result_file in RESULT_FILES:
        combined_harm_protect = \
                add_result_from_json(
                    combined_harm_protect,
                    result_file,
                    features)
    for result_file in MAKE_BINARY:
        reduced_to_binary = make_result_binary(result_file)
        combined_harm_protect = add_result_from_dict(
            combined_harm_protect,
            reduced_to_binary,
            features)

    combined_harm_protect = add_result_from_dict(
            combined_harm_protect,
            MANUALLY_ADDED_RESULTS,
            features)

    combined_harm_protect = fix_bottoms(combined_harm_protect)
    # Add color map for features.
    if GROUPED:
        combined_harm_protect[FEATURE_COLORS] = GROUPED_COLORS
    else:
        combined_harm_protect[FEATURE_COLORS] = COLORS
    with open(HARM_PROTECT_DATA, "w") as ouf:
        json.dump(combined_harm_protect, sort_keys=True, indent=2, fp=ouf)

# Json needs to be a dict of browser pack_hash keys, mapped to a dict with
# features and corresponding int values
def add_result_from_json(current_result, result_file, features):
    with open(result_file, "r") as inf:
        res = json.load(inf)
        return add_result_from_dict(current_result, res, features)

def add_result_from_dict(current_result, res, features):
    for pack_hash, feat_scores in res.items():
        feat_scores_to_consider = {}
        for feature, score in feat_scores.items():
            if feature in features:
                feat_scores_to_consider[feature] = score
        if pack_hash in current_result:
            current_result[pack_hash].update(feat_scores_to_consider)
        else:
            current_result[pack_hash] = feat_scores_to_consider
    return current_result

def make_result_binary(result_file):
    # Implicitly drops 0 scored features.
    ret_result = {}
    with open(result_file, "r") as inf:
        res = json.load(inf)
        for browser, feature_scores in res.items():
            temp_feature_scores = {}
            for feature, score in feature_scores.items():
                if score > 0:
                    temp_feature_scores[feature] = 1
                elif score < 0:
                    temp_feature_scores[feature] = -1
                # Drops the 0 scored features here.
            ret_result[browser] = temp_feature_scores
    return ret_result

# For each feature, the bottom is the combination of all previous features.
# Feature ordering is defined above
def fix_bottoms(combined_harm_protect):
    ret_dict = {}
    if GROUPED:
        good_feat = GROUPED_GOOD_FEATURES
        bad_feat = GROUPED_BAD_FEATURES
    else:
        good_feat = GOOD_FEATURES
        bad_feat = BAD_FEATURES
    for k, v in combined_harm_protect.items():
        this_res = {}
        for k1, v1 in v.items():
            this_res[k1] = v1
            bottom = 0
            if k1 in good_feat:
                bottom_list = good_feat
            elif k1 in bad_feat:
                bottom_list = bad_feat
            else:
                print("FEATURE NOT SUPPORTED!!", k1)
                continue
            for feature in bottom_list:
                if feature != k1 and feature in v:
                    bottom += v[feature]
                elif feature == k1:
                    break
            this_res[k1 + BOTTOM_KEY] = bottom
        ret_dict[k] = this_res
    return ret_dict

if __name__ == "__main__":
    main()
