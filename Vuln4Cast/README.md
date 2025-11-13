# Vuln4Cast

## What is this repository all about?
This repository holds the code that uses NVD data to demonstrate that it is possible to forecast vulnerabilities with reasonable accuracy both quarterly and yearly. We believe this is foundational rather than an end result. In other words, this forecasting will enable other research to be performed that might not have existed before. We encourage you to make more accurate forecasts, or extend the lookahead window, or make sub-forecasts for specific vendors.

## Quickstart

Clone this repository, configure a suitable Python 3 and Jupyter Notebook environment.

```
git clone https://github.com/FIRSTdotorg/Vuln4Cast.git
cd Vuln4Cast
pip install -r requirements.txt
```

Before running the analysis, you will need to run the code to fetch NVD data, see `NVDDataFetch-V1.ipynb`. This builds directory structures, fetches data from NVD (and CVE), and unpacks that data into formats that are easier to work with. This will take a few minutes depending on your network.


## Analysis

Once the data has been fetched, you can run either the quarterly or yearly forecasts, e.g. `YearlyVuln4Cast-V1.ipynb`. They each use a Sarimax model that gives good results, and we consider as a benchmark for your own research to beat. They also contain a hurst exponent analysis that should demonstrate that it is both possible to forecast, and there is long term trending in the data. Other graphs help demonstrate features useful to forecasters who will wish to extend or improve the work.