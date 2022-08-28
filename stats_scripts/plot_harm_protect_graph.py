#!/usr/bin/env python3
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import json

plt.rcParams['legend.fontsize'] = '6'
plt.rcParams['axes.labelsize'] = '6'
plt.rcParams['axes.titlesize'] = '7'
plt.rcParams['lines.linewidth'] = '0.01'
plt.rcParams['xtick.labelsize'] = '7'
plt.rcParams['ytick.labelsize'] = '6'

plt.rcParams['grid.color'] = 'gray'
plt.rcParams['grid.linestyle'] = ':'
plt.rcParams['grid.linewidth'] = 0.5

plt.rcParams['patch.force_edgecolor'] = True
plt.rcParams['patch.facecolor'] = 'b'

# plt.rcParams['xtick.direction'] = 'in'
# plt.rcParams['ytick.direction'] = 'in'
plt.rcParams['xtick.major.size'] = '3'
plt.rcParams['ytick.major.size'] = '3'
plt.rcParams['xtick.major.width'] = '0.5'
plt.rcParams['ytick.major.width'] = '0.5'

plt.rcParams['legend.fancybox'] = False
plt.rcParams['legend.framealpha'] = None

HARM_PROTECT_DATA = "combined_stats/harm_protect.json"
HARM_PROTECT_FIG = "combined_stats/harm_protect.pdf"
FEATURE_COLORS = "FEATURE_COLOR_MAP"

BOTTOM_KEY = "_bottom"

def main():
    # Get all results here
    colors, result_df = get_browser_features()
    # fig, ax = plt.subplots()
    fig = plt.figure(figsize=(6.25122, 1.8))
    fig.set_tight_layout({"pad": 0, "rect": [0, 0, .999, 1]})
    ax = fig.add_subplot(111)

    for feature, color in colors:
        if feature.endswith(BOTTOM_KEY):
            continue
        else:
            plt.bar(result_df.index, result_df[feature],
                    bottom=result_df[feature + BOTTOM_KEY],
                    color=color, width=.8, linewidth=0)

    plt.xlim([-3, len(result_df) + 2])
    ax.set_axisbelow(True)
    # ax.xaxis.grid(color='gray', linestyle='dashed', alpha=0.7)
    ax.yaxis.grid(color='gray', linestyle='dashed', alpha=0.7)
    # ax.xaxis.grid(color='gray', linestyle='dashed')
    # plt.xticks(range(0, len(result_df)), range(0, len(result_df)))# title and legend
    plt.tick_params(axis='x', which='both', bottom=False, top=False, labelbottom=False)
    legend_label = []
    for feature, color in colors:
        if not feature.endswith(BOTTOM_KEY):
            legend_label.append(feature)
    plt.legend(legend_label, ncol = 3, loc='lower left' ) # bbox_to_anchor=([-1, 0, 0, 0]), frameon = False)
    # plt.title("Combined good and bad features of " +
    #        str(len(result_df)) + " browsers", loc='center')
    # plt.xlabel("Browsers")
    plt.ylabel("Privacy-protecting(+) and\n-harming(-) features")
    print("Writing result of", str(len(result_df)), "browsers to", HARM_PROTECT_FIG)
    plt.savefig(HARM_PROTECT_FIG, dpi=2000)
    # plt.show()
    plt.close()

def get_browser_features():
    with open(HARM_PROTECT_DATA, "r") as inf:
        data = json.load(inf)
    # Save feature to color map
    colors = data[FEATURE_COLORS]
    print("Will plot colors in the order:", colors)
    del data[FEATURE_COLORS]
    # Sort the data based on the order in which browser bars are generated
    # [('browser_2', {'feat_1': 2, 'feat_2': -2}),
    # ('browesr_1', {'feat_1': 1, 'feat_2': -1})]
    # We get a list of tuples sorted by range
    data_sorted = sorted(data.items(), key=get_range, reverse=True)
    data_sorted, removed = drop_empty_bars(data_sorted)
    print("Generated plot for ", len(data_sorted), "browsers and dropped", removed)
    # Init dict for data frame
    data_dict = {}
    for feature, color in colors:
        data_dict[feature] = []
    # Fill it with values we just sorted
    for browser, feature_map in data_sorted:
        for feature, color in colors:
            if feature in feature_map:
                data_dict[feature].append(feature_map[feature])
            else:
                data_dict[feature].append(0)
    # Check if data is good
    for k, v in data_dict.items():
        print(k, len(v))
    return colors, pd.DataFrame(data_dict)

def drop_empty_bars(data_sorted):
    new_data_sorted = []
    removed = 0
    for browser, feature_dict in data_sorted:
        add = False
        for feature, score in feature_dict.items():
            if score != 0:
                add = True
        if add:
            new_data_sorted.append((browser, feature_dict))
        else:
            removed += 1
    return new_data_sorted, removed

def get_range(kvp):
    range = 0
    for v in kvp[1].values():
        range += v
    return range

if __name__ == "__main__":
    main()
