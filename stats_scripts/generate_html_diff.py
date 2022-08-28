#!/usr/bin/env python3
import argparse
import json
import sys
import difflib
import os
from bs4 import BeautifulSoup
from bs4.element import Comment
from string import digits, punctuation

remove_digits = str.maketrans('', '', digits + punctuation)
ignore_doms = []

def find_ngrams(content, n, tags_only=False):
    input_list = text_from_html(content).lower().translate(remove_digits).split()
    return [''.join(elem) for elem in list(zip(*[input_list[i:] for i in range(n)]))]

def jaccard_similarity(list1, list2):
    s1 = set(list1)
    s2 = set(list2)
    x = len(s1.union(s2))
    if x == 0:
        return 1
    return len(s1.intersection(s2)) / x

def tag_visible(element):
    if element.parent.name in ['style', 'script', 'head', 'title', 'meta', '[document]']:
        return False
    if isinstance(element, Comment):
        return False
    return True

def text_from_html(body, just_tags=False):
    soup = BeautifulSoup(body, 'html.parser')
    if just_tags:
        return u" ".join([tag.name for tag in soup.find_all()])
    texts = soup.findAll(text=True)
    visible_texts = filter(tag_visible, texts)
    return u" ".join(t.strip() for t in visible_texts)

# Difference between two pages, using entire elements.
def html_element_diff(content1, content2, text_only=False):
    soup1 = BeautifulSoup(content1, 'html.parser').find_all()
    soup2 = BeautifulSoup(content2, 'html.parser').find_all()
    if text_only:
        text1 = set(soup1.findAll(text=True))
        text2 = set(soup2.findAll(text=True))
        return list(text2 - text1), list(text1 - text2)
    s21 = [str(i) for i in set(soup2) - set(soup1)]
    s12 = [str(i) for i in set(soup1) - set(soup2)]
    return s21, s12

# Difference in scripts between two pages.
def html_script_diff(content1, content2s):
    soup1 = BeautifulSoup(content1, 'html.parser').find_all("script")
    soup2 = []
    for content2 in content2s:
        soup2.extend(BeautifulSoup(content2, 'html.parser').find_all("script"))
    s21 = [str(i) for i in set(soup2) - set(soup1)]
    s12 = [str(i) for i in set(soup1) - set(soup2)]
    sintersect = [str(i) for i in set(soup1).intersection(set(soup2))]
    return s21, s12, sintersect

def cleanup_html(html):
    # Strip mitm-tripwire
    soup = BeautifulSoup(html, 'html.parser')
    for s in soup.findAll("script", id="mitm-tripwire"):
        s.decompose()
    return soup.prettify()

def link_differences(p1, p2s):
    # Keep in mind ordering of these pages to figure out whats extra and whats missing.
    soup1 = BeautifulSoup(p1, 'html.parser')
    p2l = set()
    for p2 in p2s:
        soup2 = BeautifulSoup(p2, 'html.parser')
        tmp = set([e.get('href') for e in soup2.find_all('a')])
        p2l.update(tmp)
    # Lets see if links are missing/added.
    p1l = set([e.get('href') for e in soup1.find_all('a')])
    return list(p2l - p1l), list(p1l - p2l), list(p1l.intersection(p2l))

def get_all_links_scripts(content):
    soup = BeautifulSoup(content, 'html.parser')
    links = set([e.get('href') for e in soup.find_all('a')])
    scripts = set([str(s) for s in set(soup.find_all('script'))])
    return list(links), list(scripts)

# All tag difference
def html_tag_difference(content1, content2):
    soup1 = BeautifulSoup(content1, 'html.parser').find_all()
    soup2 = BeautifulSoup(content2, 'html.parser').find_all()
    s21 = [str(i) for i in set(soup2) - set(soup1)]
    s12 = [str(i) for i in set(soup1) - set(soup2)]
    sintersect = [str(i) for i in set(soup1).intersection(set(soup2))]
    return s21, s12, sintersect

def get_baselines(baseline_file_postfix):
    baseline_dir = "/".join(baseline_file_postfix.split("/")[:-1])
    baseline_postfix = baseline_file_postfix.split("/")[-1]
    baseline_json_list = []
    for baseline in os.listdir(baseline_dir):
        if baseline.endswith( baseline_postfix + ".upload"):
            with open(baseline_dir + "/" + baseline, "rb") as infile:
                baseline_json_list.append(json.load(infile))
    return baseline_json_list

def in_baselines(domain, baselines):
    for baseline in baselines:
        if domain in baseline:
            return True
    return False

def main():
    parser = argparse.ArgumentParser(description='HTML difference generator.')
    parser.add_argument('--baseline', help='Baseline result upload file.', type=str, nargs='?', required=True)
    parser.add_argument('--browser', help='Browser upload file to compare to baseline.', type=str, nargs='?', required=True)
    parser.add_argument('--results', help='Results file to write stats to.', type=str, nargs='?', default='htmlDiffStats.json')
    args = parser.parse_args(sys.argv[1:])
    baseline_file = args.baseline
    browser_file = args.browser
    results_file = args.results
    browser_package_name = browser_file.split("/")[-1]
    print("Processing:", browser_file)
    try:
        with open(browser_file, "r") as in2:
            baselines = get_baselines(baseline_file)
            browser = json.load(in2)
    except FileNotFoundError:
        print("Baseline/Browser file not found :/")
        return
    except json.decoder.JSONDecodeError:
        print("Error decoding baseline/browser file :/")
        return
    # Load in previously saved results
    saved_results = {}
    try:
        with open(results_file, "r") as inf:
            saved_results = json.load(inf)
    except json.decoder.JSONDecodeError:
        print("Invalid json found at: " + results_file + ", will be overwritten...")
    except FileNotFoundError:
        print("File", results_file, "not found, will create it and write...")
    # Process multiple baselines now
    # Process baseline json to a useful format for here.
    new_baselines_list = []
    for baseline in baselines:
        new_base = {}
        for k in baseline.keys():
            # Drop /flow_id/upload and save just loadedHTML.
            new_base["".join(k.split("/")[2:-2])] = cleanup_html(baseline[k]["loadedHTML"])
        new_baselines_list.append(new_base)
    baselines = new_baselines_list
    to_write = {} # JSON Stats to write.
    # Process only requests that belong to the baseline, allStats file must have new requests saved.
    for brow_key in browser.keys():
        brow_dom = "".join(brow_key.split("/")[2:-2])
        if not in_baselines(brow_dom, baselines):
            continue
        if brow_dom in ignore_doms:
            continue
        page_stat = {}
        browser_content = cleanup_html(browser[brow_key]["loadedHTML"])
        # baseline_content = baseline[brow_dom] # HTML already cleaned up.

        # # Content similarity using ngram of visible text.
        # browser_ngram = find_ngrams(browser_content, 5)
        # baseline_ngram = find_ngrams(baseline_content, 5)
        # visible_text_distance = 1 - jaccard_similarity(baseline_ngram, browser_ngram)

        # # Let's save the visible text distance in case its greater than 0.
        # if visible_text_distance > 0:
        #     page_stat["visible_distance"] = visible_text_distance
        #     browser_1gram = set(find_ngrams(browser_content, 1))
        #     baseline_1gram = set(find_ngrams(baseline_content, 1))
        #     # Let's save the missing/extra ngrams for later.
        #     page_stat["missing_1grams"] = list(baseline_1gram - browser_1gram)
        #     page_stat["extra_1grams"] = list(browser_1gram - baseline_1gram)

        baseline_contents = []
        for baseline in baselines:
            if brow_dom in baseline:
                baseline_contents.append(baseline[brow_dom])
        # Extract and process links
        links_missing, links_extra, links_overlap = link_differences(browser_content, baseline_contents)
        if len(links_extra) > 0:
            page_stat["extra_links"] = links_extra
        if len(links_missing) > 0:
            page_stat["missing_links"] = links_missing
        if len(links_overlap) > 0:
            page_stat["overlap_links"] = links_overlap

        # Process html tag differences
        scripts_missing, scripts_extra, scripts_overlap = html_script_diff(browser_content, baseline_contents)
        if len(scripts_missing) > 0:
            page_stat["missing_scripts"] = list(scripts_missing)
        if len(scripts_extra) > 0:
            page_stat["extra_scripts"] = list(scripts_extra)
        if len(scripts_overlap) > 0:
            page_stat["overlap_scripts"] = list(scripts_overlap)

        # Save all links and scripts seen rendered by a browser
        all_links, all_scripts = get_all_links_scripts(browser_content)
        if len(all_links) > 0:
            page_stat["all_links"] = all_links
        if len(all_scripts) > 0:
            page_stat["all_scripts"] = all_scripts

        # Save this page's stats.
        if len(page_stat) > 0:
            to_write[brow_dom] = page_stat
    # Write all results to the results file.
    print("Done processing all common pages.")
    saved_results[browser_package_name] = to_write
    with open(results_file, "w+") as outfile:
        try:
            json.dump(saved_results, fp=outfile, sort_keys=True, indent=2)
        except:
            print("Error dumping json to results file.")
            return
    print("Done writing results.")

if __name__ == "__main__":
    main()
