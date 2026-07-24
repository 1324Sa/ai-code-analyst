# 🛡️ AI Code Analyst & Systems Engineer

> **Next-Generation Static Analysis, Symbolic Execution & AST Taint Flow Engine**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)](https://www.python.org/)
[![React](https://img.shields.io/badge/React-18.0%2B-61DAFB?logo=react)](https://reactjs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0%2B-3178C6?logo=typescript)](https://www.typescript.org/)
[![Compliance](https://img.shields.io/badge/Compliance-PCI--DSS%20v4.0%20%7C%20NIST-emerald)](#multi-standard-compliance)

---

## 📌 Executive Summary

**AI Code Analyst & Systems Engineer** is an enterprise-grade security analysis and data-flow tracing platform. By combining Abstract Syntax Tree (AST) parsing, symbolic execution, and LLM-driven reasoning, it traces untrusted data inputs from their entry points (Sources) all the way down to sensitive internal operations (Sinks).

Unlike traditional static analysis tools that rely on simplistic pattern matching, this engine performs **interprocedural taint analysis**, constructs dynamic **Taint Flow Graphs**, maps vulnerabilities directly to global compliance standards (**CWE**, **PCI-DSS v4.0**, **NIST**), and generates deterministic patch proposals (`git diff`).

---

## 🔥 Key Technical Capabilities

* 🌳 **Deep AST & Static Parsing**: Constructs complete syntax trees to inspect scope, control flows, and un-sanitized variable propagations across functions.
* 🕸️ **Interactive Taint Flow Graphing**: Renders complex data propagation flows visually with custom node styling (Sources vs. Transformations vs. Sinks).
* 🛡️ **Multi-Standard Compliance Mapping**: Automatically tags findings with official identifiers:
  * **CWE** (e.g., CWE-89 SQLi, CWE-78 Command Injection, CWE-502 Deserialization)
  * **PCI-DSS v4.0** (Requirements 6.2.4, 3.3.1, etc.)
  * **NIST SP 800-53** (SI-10, IA-5, SC-13, SA-11)
* ⚡ **Real-Time Coverage Tracking**: Provides live metrics on reviewed vs. total codebase lines with explicit execution guards.
* 🛠️ **Automated Patch & Diff Generation**: Generates contextual, production-ready fixes with clean side-by-side modal comparisons.

---

## 🏗️ Architecture & Engine Overview
