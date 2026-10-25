#!/usr/bin/env python3
from functools import lru_cache
import redis
from datetime import timedelta

class CacheLayer:
    def __init__(self, redis_url='redis://localhost:6379'):
        self.redis_client = redis.from_url(redis_url, decode_responses=True)
    
    def get_findings_cached(self, org_id, ttl=3600):
        """Cache findings for 1 hour"""
        key = f"findings:{org_id}"
        cached = self.redis_client.get(key)
        if cached:
            return json.loads(cached)
        return None
    
    def set_findings_cached(self, org_id, findings, ttl=3600):
        """Cache findings"""
        key = f"findings:{org_id}"
        self.redis_client.setex(key, ttl, json.dumps(findings))
    
    def invalidate_findings(self, org_id):
        """Invalidate cache on new findings"""
        key = f"findings:{org_id}"
        self.redis_client.delete(key)

class QueryOptimizer:
    @staticmethod
    def get_findings_optimized(org_id, limit=100, offset=0):
        """Optimized query with pagination"""
        conn = get_db()
        c = conn.cursor()
        c.execute('''
            SELECT id, server_url, vector_type, severity, created_at 
            FROM findings 
            WHERE org_id = %s 
            ORDER BY created_at DESC 
            LIMIT %s OFFSET %s
        ''', (org_id, limit, offset))
        findings = c.fetchall()
        conn.close()
        return findings
    
    @staticmethod
    def create_indexes():
        """Create database indexes for performance"""
        conn = get_db()
        c = conn.cursor()
        c.execute('CREATE INDEX IF NOT EXISTS idx_findings_org ON findings(org_id)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_findings_created ON findings(created_at)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_orgs_key ON organizations(api_key)')
        conn.commit()
        conn.close()
