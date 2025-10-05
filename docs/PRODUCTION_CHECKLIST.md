# Production Security Hardening - Pre-Deployment Checklist

**⚠️ CRITICAL: Complete ALL items before running `hardening-tool apply` on production systems**

## Pre-Deployment Requirements

### 🧪 Testing & Validation
- [ ] **Dry-run executed** and reviewed: `hardening-tool apply --dry-run`
- [ ] **Identical test environment** validated with actual apply operations
- [ ] **Application compatibility** verified after hardening changes
- [ ] **Network connectivity** tested post-hardening (SSH, RDP, services)
- [ ] **Performance impact** assessed and acceptable

### 💾 Backup & Recovery
- [ ] **Complete system backup** created and verified
- [ ] **Configuration files** backed up to secure, encrypted storage
- [ ] **Database snapshots** completed (if applicable)
- [ ] **VM snapshots** created (virtualized environments)
- [ ] **Backup integrity** tested and restoration verified

### 🔄 Rollback Preparation
- [ ] **Rollback procedure** documented and tested
- [ ] **Rollback timeframe** estimated and approved
- [ ] **Recovery contact list** prepared and accessible
- [ ] **Emergency access** methods confirmed (console, out-of-band)

### 🔒 Security & Access
- [ ] **Backup encryption** enabled with secure key management
- [ ] **Access controls** reviewed - limit who can execute hardening
- [ ] **Audit logging** enabled for all hardening activities
- [ ] **Security team approval** obtained for production changes
- [ ] **Change management ticket** created and approved

### ⏰ Operational Readiness
- [ ] **Maintenance window** scheduled and communicated
- [ ] **Stakeholder notification** sent (affected teams, users)
- [ ] **On-call support** arranged for post-deployment monitoring
- [ ] **Monitoring alerts** configured for system health
- [ ] **Communication plan** established for issues

### 🎯 Final Validation
- [ ] **Hardening scope** confirmed (rules, systems, impact)
- [ ] **Business continuity** plan activated if needed
- [ ] **Go/No-go decision** made by authorized personnel

**🚨 ABORT CONDITIONS:** Stop immediately if any backup fails, test environment shows issues, or approvals are missing.

**📞 EMERGENCY:** Have system recovery contacts and procedures ready before starting.