import json
import sys
from numerical import *
import matplotlib.pyplot as plt
from scipy.stats import ks_2samp
from sklearn.metrics import mutual_info_score
import numpy as np

def compare_distributions(a, b):
    # Use Kolmogorov-Smirnov test to compare distributions
    statistic, p_value = ks_2samp(a, b)
    return p_value

def compare_mutual_information(a, b):
    # Compute mutual information between two arrays
    mi = mutual_info_score(np.round(a, decimals=2), np.round(b, decimals=2))
    return mi

def convert_text_numerical(data_list):
    numerical_data = []
    for item in data_list:
        cvssV3 = item.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {})
        numerical_cvssV3 = {
            'attackVector': AV.get(cvssV3.get('attackVector')),
            'attackComplexity': AC.get(cvssV3.get('attackComplexity')),
            'privilegesRequired': PR.get(cvssV3.get('privilegesRequired')),
            'userInteraction': UI.get(cvssV3.get('userInteraction')),
            'scope': S.get(cvssV3.get('scope')),
            'confidentialityImpact': C.get(cvssV3.get('confidentialityImpact')),
            'integrityImpact': I.get(cvssV3.get('integrityImpact')),
            'availabilityImpact': A.get(cvssV3.get('availabilityImpact')),
            'exploitabilityScore': item.get('impact', {}).get('baseMetricV3', {}).get('exploitabilityScore'),
            'impactScore': item.get('impact', {}).get('baseMetricV3', {}).get('impactScore')
        }
        numerical_data.append(numerical_cvssV3)
    return numerical_data

def compare_vec_impact(reg_data, total_data):
    reg = convert_text_numerical(reg_data)
    total = convert_text_numerical(total_data)

    # Convert to NumPy arrays
    reg_exploitability = np.array([d['exploitabilityScore'] for d in reg if d['exploitabilityScore'] is not None])
    total_exploitability = np.array([d['exploitabilityScore'] for d in total if d['exploitabilityScore'] is not None])

    reg_impact = np.array([d['impactScore'] for d in reg if d['impactScore'] is not None])
    total_impact = np.array([d['impactScore'] for d in total if d['impactScore'] is not None])

    p_value_exploitability = compare_distributions(reg_exploitability, total_exploitability)
    p_value_impact = compare_distributions(reg_impact, total_impact)

    mi_exploitability = compare_mutual_information(reg_exploitability, total_exploitability)
    mi_impact = compare_mutual_information(reg_impact, total_impact)

    # Plot histograms
    metrics = ['attackVector', 'attackComplexity', 'privilegesRequired', 'userInteraction', 'scope', 'confidentialityImpact', 'integrityImpact', 'availabilityImpact']
    for metric in metrics:
        reg_metric = np.array([d[metric] for d in reg if d[metric] is not None])
        total_metric = np.array([d[metric] for d in total if d[metric] is not None])

        plt.hist(reg_metric, bins=20, alpha=0.5, label='Reg')
        plt.hist(total_metric, bins=20, alpha=0.5, label='Total')
        plt.title(metric)
        plt.legend()
        plt.show()

    return (p_value_exploitability, p_value_impact), (mi_exploitability, mi_impact)

def extract_statistics(reg_path, full_path):
    print("alou")
    # Read JSON files
    with open(reg_path, 'r') as f:
        reg_data = json.load(f)
    with open("data/nvdcve-1.1-modified.json", encoding="utf8") as file:
        print(json.load(file))
        total_data = json.load(file)

    total_data = total_data["CVE_Items"]

    print(f"Percentage of regression cases: {len(reg_data)/len(total_data)*100}%")

    (cd_exploitability, cd_impact), (mi_exploitability, mi_impact) = compare_vec_impact(reg_data, total_data)

    print(f"p-value of exploitability scores comparison: {cd_exploitability}")
    print(f"Mutual information of exploitability scores: {mi_exploitability}")
    print(f"p-value of impact scores comparison: {cd_impact}")
    print(f"Mutual information of impact scores: {mi_impact}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: script.py reg_path full_path")
    else:
        reg_path = sys.argv[1]
        full_path = sys.argv[2]
        extract_statistics(reg_path, full_path)

