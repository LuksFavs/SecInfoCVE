import json
import sys
from numerical import *
import matplotlib.pyplot as plt
from scipy.stats import ks_2samp, ttest_ind
import numpy as np
import datetime
from collections import Counter, defaultdict

def print_statistics(data, label, outfile):
    """
    Print mean, variance, and quantiles of the data into the output file.
    """
    mean_val = np.mean(data)
    var_val = np.var(data)
    q25 = np.percentile(data, 25)
    q50 = np.median(data)
    q75 = np.percentile(data, 75)

    outfile.write(f"=== {label} Statistics ===\n")
    outfile.write(f"Count: {len(data)}\n")
    outfile.write(f"Mean: {mean_val}\n")
    outfile.write(f"Variance: {var_val}\n")
    outfile.write(f"25th Percentile: {q25}\n")
    outfile.write(f"Median (50th): {q50}\n")
    outfile.write(f"75th Percentile: {q75}\n\n")

def compare_distributions(a, b, label_a='Reg', label_b='Total', title='Distribution Comparison', outfile=None):
    """
    Compare two distributions using the Kolmogorov-Smirnov test and two-sample t-test.
    Also plot and save the distributions.
    """
    # KS Test
    ks_stat, ks_p_value = ks_2samp(a, b)
    # T-test
    t_stat, t_p_value = ttest_ind(a, b, equal_var=False)  # Welch's t-test, safer if variances differ
    
    # Plot the distributions
    plt.figure(figsize=(10, 6))
    plt.hist(a, bins=20, alpha=0.5, label=label_a, density=True)
    plt.hist(b, bins=20, alpha=0.5, label=label_b, density=True)
    plt.title(title)
    plt.xlabel('Value')
    plt.ylabel('Density')
    plt.legend()
    plt.savefig(f"out/img/{title.replace(' ', '_')}.png")
    plt.close()
    
    if outfile is not None:
        outfile.write(f"=== {title} Comparison ===\n")
        outfile.write(f"Kolmogorov-Smirnov Test: statistic={ks_stat}, p-value={ks_p_value}\n")
        outfile.write(f"T-test (Welch): statistic={t_stat}, p-value={t_p_value}\n\n")

    return ks_p_value, t_p_value

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
            'impactScore': item.get('impact', {}).get('baseMetricV3', {}).get('impactScore'),
            'publishedDate': item.get('publishedDate')
        }
        numerical_data.append(numerical_cvssV3)
    return numerical_data

def time_analysis(reg_data, total_data):
    """
    Perform a time-based analysis by counting the occurrences of CVEs per month
    for regression and total sets, and plotting the results.
    """
    # Extract and parse published dates
    def parse_date(date_str):
        # Assuming format like: "2021-01-01T10:00Z"
        return datetime.datetime.strptime(date_str, "%Y-%m-%dT%H:%MZ")

    reg_dates = [parse_date(d['publishedDate']) for d in reg_data if d['publishedDate'] is not None]
    total_dates = [parse_date(d['publishedDate']) for d in total_data if d['publishedDate'] is not None]

    def count_per_month(dates):
        month_counts = Counter((d.year, d.month) for d in dates)
        # Sort by year-month
        sorted_keys = sorted(month_counts.keys())
        x = [datetime.date(y, m, 1) for (y, m) in sorted_keys]
        y = [month_counts[(y, m)] for (y, m) in sorted_keys]
        return x, y
    
    x_reg, y_reg = count_per_month(reg_dates)
    x_tot, y_tot = count_per_month(total_dates)

    plt.figure(figsize=(10, 6))
    plt.plot(x_tot, y_tot, label='Total CVEs', marker='o')
    plt.plot(x_reg, y_reg, label='Regression CVEs', marker='o')
    plt.title("CVEs Over Time")
    plt.xlabel("Date (Year-Month)")
    plt.ylabel("Count of CVEs")
    plt.legend()
    plt.grid(True)
    plt.savefig("out/img/Time_Analysis.png")
    plt.close()

def compare_vec_impact(reg_data, total_data, outfile):
    reg = convert_text_numerical(reg_data)
    total = convert_text_numerical(total_data)
    
    # Convert to NumPy arrays
    reg_exploitability = np.array([d['exploitabilityScore'] for d in reg if d['exploitabilityScore'] is not None])
    total_exploitability = np.array([d['exploitabilityScore'] for d in total if d['exploitabilityScore'] is not None])
    
    reg_impact = np.array([d['impactScore'] for d in reg if d['impactScore'] is not None])
    total_impact = np.array([d['impactScore'] for d in total if d['impactScore'] is not None])

    reg_base = np.array([d['baseScore'] for d in reg if d['baseScore'] is not None])
    total_base = np.array([d['baseScore'] for d in total if d['baseScore'] is not None])
    
    # Print stats for each distribution
    print_statistics(reg_exploitability, "Regression Exploitability Score", outfile)
    print_statistics(total_exploitability, "Total Exploitability Score", outfile)
    print_statistics(reg_impact, "Regression Impact Score", outfile)
    print_statistics(total_impact, "Total Impact Score", outfile)
    print_statistics(reg_base, "Regression Base Score", outfile)
    print_statistics(total_base, "Total Base Score", outfile)

    # Compare exploitability scores
    ks_p_exploitability, t_p_exploitability = compare_distributions(
        reg_exploitability, total_exploitability,
        label_a='Reg Exploitability', label_b='Total Exploitability',
        title='Exploitability_Score_Distribution', outfile=outfile
    )
    
    # Compare impact scores
    ks_p_impact, t_p_impact = compare_distributions(
        reg_impact, total_impact,
        label_a='Reg Impact', label_b='Total Impact',
        title='Impact_Score_Distribution', outfile=outfile
    )
    
    # Compare base scores
    ks_p_base, t_p_base = compare_distributions(
        reg_base, total_base,
        label_a='Reg Base', label_b='Total Base',
        title='Base_Score_Distribution', outfile=outfile
    )

    # Boxplots for visual inspection
    plt.boxplot([reg_base, total_base], labels=['BaseScore Regression', 'BaseScore Total'])
    plt.title("Base Score Boxplot Comparison")
    plt.savefig("out/img/BaseScore_Boxplot.png")
    plt.close()
    
    plt.boxplot([reg_impact, total_impact], labels=['ImpactScore Regression', 'ImpactScore Total'])
    plt.title("Impact Score Boxplot Comparison")
    plt.savefig("out/img/ImpactScore_Boxplot.png")
    plt.close()
    
    plt.boxplot([reg_exploitability, total_exploitability], labels=['ExploitabilityScore Regression', 'ExploitabilityScore Total'])
    plt.title("Exploitability Score Boxplot Comparison")
    plt.savefig("out/img/ExploitabilityScore_Boxplot.png")
    plt.close()
    
    # Histograms for categorical metrics
    metrics = ['attackVector', 'attackComplexity', 'privilegesRequired', 'userInteraction', 'scope', 'confidentialityImpact', 'integrityImpact', 'availabilityImpact']
    for metric in metrics:
        reg_metric = np.array([d[metric] for d in reg if d[metric] is not None])
        total_metric = np.array([d[metric] for d in total if d[metric] is not None])

        if len(reg_metric) > 0 and len(total_metric) > 0:
            plt.hist(reg_metric, bins=20, alpha=0.5, label='Reg')
            plt.hist(total_metric, bins=20, alpha=0.5, label='Total')
            plt.title(metric)
            plt.legend()
            plt.savefig(f"out/img/{metric}_Histogram.png")
            plt.close()

    return (ks_p_exploitability, ks_p_impact, ks_p_base, t_p_exploitability, t_p_impact, t_p_base, reg, total)

def extract_statistics(reg_path, full_path):
    # Read JSON files
    with open(reg_path, 'r') as f:
        reg_data = json.load(f)
    with open(full_path, encoding="utf8") as file:
        total_data = json.load(file)

    total_data = total_data["CVE_Items"]

    with open("out/results.txt", "w") as outfile:
        percentage = (len(reg_data)/len(total_data))*100
        outfile.write(f"Percentage of regression cases: {percentage}%\n\n")

        (ks_expl, ks_imp, ks_base,
         t_expl, t_imp, t_base,
         reg, total) = compare_vec_impact(reg_data, total_data, outfile)

        # Time analysis
        outfile.write("Performing time analysis...\n")
        time_analysis(reg, total)
        outfile.write("Time analysis plot saved as Time_Analysis.png\n")

        # Summarize statistical test p-values
        outfile.write("\n=== Summary of p-values ===\n")
        outfile.write(f"KS p-value (Exploitability): {ks_expl}\n")
        outfile.write(f"KS p-value (Impact): {ks_imp}\n")
        outfile.write(f"KS p-value (Base): {ks_base}\n\n")

        outfile.write(f"T-test p-value (Exploitability): {t_expl}\n")
        outfile.write(f"T-test p-value (Impact): {t_imp}\n")
        outfile.write(f"T-test p-value (Base): {t_base}\n")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: script.py reg_path full_path")
    else:
        reg_path = sys.argv[1]
        full_path = sys.argv[2]
        extract_statistics(reg_path, full_path)

