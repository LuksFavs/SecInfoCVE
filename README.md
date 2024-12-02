# SecInfoCVE

Before executing make sure you have the nvdcve-1.1-modified.json file decompressed in the data folder.

first execute:
python cveFilter.py

it will create the regression.json collection, after that run:
python explore.py regression.json data/nvdcve-1.1-modified.json

so that the experiment can be concluded.
