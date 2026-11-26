# File Checker

A deployment and investigation of a spoofed file found on a Windows 11 machine. Demonstrating the tool I built 
that checks the file signature specifically the header bytes.


## Purpose

I wanted to develop a better understanding of how spoofed documents and how systems validate whether they are correct or not. What better way than building the tool yourself! This version of the the “FileChecker” is meant to be a basic introduction.

## How it works

This script checks the files' ‘magic numbers’ or initial set of hex values against a known list of values that match up to file types. It creates a hash to check against VirusTotal for known malicious files and scores the file on how suspicious it might be. Finally it performs a File Analysis grouping all the data and providing a [report] (https://github.com/antnycme/CyberSecurity---File-Checker/blob/main/Reports/scan_report.csv) to the Analyst.

## True PDF
<img width="1002" height="516" alt="Real" src="https://github.com/user-attachments/assets/06d40c36-2222-4854-a4bb-4f8ad69fd8d2" />

## Spoofed PDF
<img width="998" height="576" alt="SpoofedPDF" src="https://github.com/user-attachments/assets/6e5cafef-6321-4041-a79d-097af24ef372" />

