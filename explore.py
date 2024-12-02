import json
import sys
from numerical import *
import matplotlib.pyplot as plt
from scipy.stats import ks_2samp
from sklearn.metrics import mutual_info_score
import numpy as np

def compare_distributions(a, b, label_a='Reg', label_b='Total', title='Distribution Comparison'):
    """
    Compare two distributions using the Kolmogorov-Smirnov test and plot them.
    """
    # Use Kolmogorov-Smirnov test to compare distributions
    statistic, p_value = ks_2samp(a, b)
    
    # Plot the distributions
    plt.figure(figsize=(10, 6))
    plt.hist(a, bins=20, alpha=0.5, label=label_a, density=True)
    plt.hist(b, bins=20, alpha=0.5, label=label_b, density=True)
    plt.title(title)
    plt.xlabel('Value')
    plt.ylabel('Density')
    plt.legend()
    plt.show()
    
    return p_value

def compare_mutual_information(a, b, bins=20):
    """
    Compute mutual information between two unpaired datasets by creating a 2D histogram.
    """
    # Bin the data
    c_min = min(np.min(a), np.min(b))
    c_max = max(np.max(a), np.max(b))
    bins = np.linspace(c_min, c_max, bins)
    
    # Digitize the data
    a_digitized = np.digitize(a, bins)
    b_digitized = np.digitize(b, bins)
    
    # Create a joint histogram
    contingency_table = np.histogram2d(a, b, bins=[bins, bins])[0]
    
    # Flatten the contingency table
    contingency_table = contingency_table.astype(int)
    contingency_table = contingency_table.flatten()
    
    # Compute mutual information
    mi = mutual_info_score(None, None, contingency=contingency_table)
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
            'baseScore': cvssV3.get('baseScore'),
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

    reg_base = np.array([d['baseScore'] for d in reg if d['baseScore'] is not None])
    total_base = np.array([d['baseScore'] for d in total if d['baseScore'] is not None])
    

    # Compare exploitability scores
    p_value_exploitability = compare_distributions(
        reg_exploitability, total_exploitability,
        label_a='Reg Exploitability', label_b='Total Exploitability',
        title='Exploitability Score Distribution'
    )
    
    #mi_exploitability = compare_mutual_information(reg_exploitability, total_exploitability)
    
    # Compare impact scores
    p_value_impact = compare_distributions(
        reg_impact, total_impact,
        label_a='Reg Impact', label_b='Total Impact',
        title='Impact Score Distribution'
    )
    
    p_value_base = compare_distributions(
        reg_base, total_base,
        label_a='Reg Base', label_b='Total Base',
        title='Base Score Distribution'
    )

    plt.boxplot([reg_base, total_base], tick_labels=['BaseScore Regression', 'BaseScore Total'])
    plt.show()
    plt.boxplot([reg_impact, total_impact], tick_labels=['ImpactScore Regression', 'ImpactScore Total'])
    plt.show()
    plt.boxplot([reg_exploitability, total_exploitability], tick_labels=['ExploitabilityScore Regression', 'ExploitabilityScore Total'])
    plt.show()
    
    #mi_impact = compare_mutual_information(reg_impact, total_impact)

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

    return (p_value_exploitability, p_value_impact, p_value_base)# , (mi_exploitability, mi_impact)

def extract_statistics(reg_path, full_path):
    # Read JSON files
    with open(reg_path, 'r') as f:
        reg_data = json.load(f)
    with open(full_path, encoding="utf8") as file:
        total_data = json.load(file)

    total_data = total_data["CVE_Items"]

    print(f"Percentage of regression cases: {len(reg_data)/len(total_data)*100}%")

    (cd_exploitability, cd_impact, cd_base)  = compare_vec_impact(reg_data, total_data)

    print(f"p-value of exploitability scores comparison: {cd_exploitability}")
    #print(f"Mutual information of exploitability scores: {mi_exploitability}")
    print(f"p-value of impact scores comparison: {cd_impact}")
    #print(f"Mutual information of impact scores: {mi_impact}")
    print(f"p-value of base scores comparison: {cd_base}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: script.py reg_path full_path")
    else:
        reg_path = sys.argv[1]
        full_path = sys.argv[2]
        extract_statistics(reg_path, full_path)

