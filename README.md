# PassAudit — Password Strength Analyzer

PassAudit is a client-side password strength analyzer built using HTML, CSS, and JavaScript. It evaluates passwords in real time and provides feedback based on common security rules and patterns.

# Live Demo: https://LuckyParekh.github.io/passaudit/

## Overview

This tool analyzes a password and calculates a strength score based on factors like length, character variety, and known weak patterns. It also estimates how long it would take to crack the password using a brute-force approach.

All analysis is done in the browser. No data is sent or stored.

## Features

- Real-time password strength scoring (0–100)
- Strength categories (Very Weak to Strong)
- Detection of common passwords
- Detection of sequential patterns (e.g. 1234, abcd)
- Detection of keyboard patterns (e.g. qwerty, asdf)
- Check for repeated characters
- Password generator
- Estimated crack time

## Tech Stack

- HTML
- CSS
- JavaScript (no frameworks)

## Project Structure
passaudit/
├── index.html
├── style.css
├── script.js
└── README.md

## Notes

This project was built to explore how password strength is evaluated and how common weaknesses can be detected programmatically.