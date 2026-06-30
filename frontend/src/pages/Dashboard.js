import React, { useState, useEffect, useCallback, useRef } from "react";
import { useNavigate } from "react-router-dom";
import {
  Chart as ChartJS, CategoryScale, LinearScale, PointElement, LineElement,
  BarElement, ArcElement, Title, Tooltip, Legend, Filler,
} from "chart.js";
import { Line, Bar, Doughnut } from "react-chartjs-2";
import { useAuth } from "../context/AuthContext";
import API from "../utils/api";
import { connectWS, disconnectWS, addWSListener, removeWSListener } from "../utils/ws";

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, BarElement, ArcElement, Title, Tooltip, Legend, Filler);

const T = {
  bg:"#0f172a", surface:"#1e293b", surface2:"#162032", border:"#334155",
  text:"#e2e8f0", muted:"#64748b", sub:"#94a3b8",
  blue:"#38bdf8", indigo:"#818cf8", green:"#4ade80",
  yellow:"#fbbf24", red:"#f87171", orange:"#fb923c", purple:"#c084fc",
};
const PIE_COLORS = ["#38bdf8","#818cf8","#fb923c","#f87171","#4ade80","#fbbf24","#e879f9","#34d399"];

// ── helpers ────────────────────────────────────────────────────────────────────
const sevBadge = (s) => {
  const m = { High:{bg:"rgba(248,113,113,0.12)",color:"#f87171",border:"rgba(248,113,113,0.3)"},
               Medium:{bg:"rgba(251,191,36,0.12)",color:"#fbbf24",border:"rgba(251,191,36,0.3)"},
               Low:{bg:"rgba(74,222,128,0.12)",color:"#4ade80",border:"rgba(74,222,128,0.3)"} };
  const st = m[s]||m.Low;
  return <span style={{padding:"2px 10px",borderRadius:20,fontSize:11,fontWeight:600,
    background:st.bg,color:st.color,border:`1px solid ${st.border}`}}>{s}</span>;
};
const fmt  = (ts) => ts ? new Date(ts).toLocaleString() : "—";
const fmtT = (ts) => ts ? new Date(ts).toLocaleTimeString() : "—";

const cOpts = (extra={}) => ({
  responsive:true, maintainAspectRatio:false,
  plugins:{ legend:{display:false},
    tooltip:{backgroundColor:"#1e293b",titleColor:T.blue,bodyColor:T.text,borderColor:T.border,borderWidth:1},
    ...extra.plugins },
  scales:{ x:{ticks:{color:T.muted,font:{size:10}},grid:{color:"rgba(255,255,255,0.04)"}},
            y:{ticks:{color:T.muted,font:{size:10}},grid:{color:"rgba(255,255,255,0.04)"}},
            ...extra.scales }, ...extra,
});

function Spinner() {
  return <div style={{display:"flex",alignItems:"center",justifyContent:"center",padding:40}}>
    <div style={{width:30,height:30,border:`3px solid ${T.border}`,borderTop:`3px solid ${T.blue}`,
      borderRadius:"50%",animation:"spin 0.8s linear infinite"}}/>
  </div>;
}
function Empty({icon,msg}) {
  return <div style={{textAlign:"center",padding:"36px 20px",color:T.muted}}>
    <div style={{fontSize:32,marginBottom:10}}>{icon}</div>
    <div style={{fontSize:13}}>{msg}</div>
  </div>;
}
function Card({title,children,height,action,style={}}) {
  return <div style={{background:T.surface,border:`1px solid ${T.border}`,borderRadius:12,
    padding:"16px 18px",marginBottom:14,...style}}>
    {title&&<div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:12}}>
      <div style={{color:T.blue,fontWeight:600,fontSize:13}}>{title}</div>{action}
    </div>}
    {height?<div style={{height}}>{children}</div>:children}
  </div>;
}
function StatCard({icon,label,value,sub,accent,loading}) {
  return <div style={{background:T.surface,border:`1px solid ${T.border}`,borderRadius:12,
    padding:"14px 16px",borderLeft:`3px solid ${accent}`,display:"flex",alignItems:"center",gap:12}}>
    <div style={{fontSize:26}}>{icon}</div>
    <div>
      <div style={{color:T.muted,fontSize:11,textTransform:"uppercase",letterSpacing:"0.5px",fontWeight:500}}>{label}</div>
      {loading
        ?<div style={{height:26,width:56,background:T.border,borderRadius:6,marginTop:4,animation:"pulse 1.5s infinite"}}/>
        :<div style={{color:accent,fontSize:24,fontWeight:700,lineHeight:1.2}}>{value??"—"}</div>}
      {sub&&<div style={{color:T.muted,fontSize:11,marginTop:1}}>{sub}</div>}
    </div>
  </div>;
}

// ── Alert Popup ────────────────────────────────────────────────────────────────
function AttackPopup({alert,onClose}) {
  useEffect(()=>{ const t=setTimeout(onClose,5000); return()=>clearTimeout(t); },[onClose]);
  return (
    <div style={{position:"fixed",top:20,right:20,zIndex:10000,width:340,
      background:"#1a0a0a",border:"2px solid #f87171",borderRadius:12,
      padding:"16px 18px",boxShadow:"0 0 40px rgba(248,113,113,0.3)",animation:"fadeIn 0.3s ease"}}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start"}}>
        <div style={{display:"flex",gap:10,alignItems:"center"}}>
          <span style={{fontSize:24}}>⚠️</span>
          <div>
            <div style={{color:"#f87171",fontWeight:700,fontSize:14}}>Attack Detected!</div>
            <div style={{color:"#fca5a5",fontSize:12,marginTop:2}}>{alert.attack_type}</div>
          </div>
        </div>
        <button onClick={onClose} style={{background:"none",border:"none",color:T.muted,cursor:"pointer",fontSize:18,lineHeight:1}}>×</button>
      </div>
      <div style={{marginTop:12,display:"grid",gridTemplateColumns:"1fr 1fr",gap:8}}>
        {[["Risk Score",`${alert.risk_score?.toFixed(1)}/100`],["Severity",alert.severity],
          ["Anomaly Score",alert.anomaly_score?.toFixed(4)],["Alert ID",`#${alert.alert_id}`]]
          .map(([k,v])=><div key={k} style={{background:"rgba(248,113,113,0.08)",borderRadius:6,padding:"6px 8px"}}>
            <div style={{color:T.muted,fontSize:10}}>{k}</div>
            <div style={{color:"#fca5a5",fontWeight:600,fontSize:12}}>{v}</div>
          </div>)}
      </div>
      <div style={{marginTop:10,height:3,background:"rgba(248,113,113,0.2)",borderRadius:2}}>
        <div style={{height:"100%",background:"#f87171",borderRadius:2,
          animation:"shrink 5s linear forwards"}}/>
      </div>
    </div>
  );
}

// ── Metric Gauge ──────────────────────────────────────────────────────────────
function MetricGauge({label,value,color}) {
  return <div style={{textAlign:"center"}}>
    <div style={{position:"relative",width:90,height:90,margin:"0 auto 8px"}}>
      <svg viewBox="0 0 36 36" style={{width:90,height:90,transform:"rotate(-90deg)"}}>
        <circle cx="18" cy="18" r="15.9" fill="none" stroke={T.border} strokeWidth="3"/>
        <circle cx="18" cy="18" r="15.9" fill="none" stroke={color} strokeWidth="3"
          strokeDasharray={`${value} 100`} strokeLinecap="round"/>
      </svg>
      <div style={{position:"absolute",top:"50%",left:"50%",transform:"translate(-50%,-50%)",
        color,fontWeight:700,fontSize:15}}>{value}%</div>
    </div>
    <div style={{color:T.sub,fontSize:12,fontWeight:500}}>{label}</div>
  </div>;
}

// ── Confusion Matrix ───────────────────────────────────────────────────────────
function ConfusionMatrix({matrix,classes,title}) {
  if(!matrix||!classes) return null;
  const max = Math.max(...matrix.flat());
  const shortClass = (c) => c.length > 8 ? c.slice(0,8)+"…" : c;
  return (
    <div>
      <div style={{color:T.sub,fontSize:12,marginBottom:10,textAlign:"center"}}>{title}</div>
      <div style={{overflowX:"auto"}}>
        <table style={{borderCollapse:"collapse",fontSize:10,margin:"0 auto"}}>
          <thead>
            <tr>
              <td style={{padding:"4px 6px",color:T.muted,fontSize:9}}>Act\Pred</td>
              {classes.map(c=><th key={c} style={{padding:"4px 6px",color:T.blue,fontWeight:600,
                fontSize:9,textAlign:"center",maxWidth:60}}>{shortClass(c)}</th>)}
            </tr>
          </thead>
          <tbody>
            {matrix.map((row,i)=>(
              <tr key={i}>
                <td style={{padding:"4px 6px",color:T.blue,fontWeight:600,fontSize:9,
                  whiteSpace:"nowrap"}}>{shortClass(classes[i])}</td>
                {row.map((val,j)=>{
                  const intensity = max>0?val/max:0;
                  const isDiag = i===j;
                  const bg = isDiag
                    ? `rgba(74,222,128,${0.1+intensity*0.7})`
                    : val>0 ? `rgba(248,113,113,${0.05+intensity*0.6})` : "transparent";
                  return <td key={j} style={{padding:"5px 8px",textAlign:"center",
                    background:bg,borderRadius:4,margin:2,
                    color:isDiag?(val>0?"#4ade80":T.muted):(val>0?"#f87171":T.muted),
                    fontWeight:isDiag?700:400,fontSize:11}}>{val}</td>;
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div style={{display:"flex",gap:16,justifyContent:"center",marginTop:10,fontSize:11,color:T.muted}}>
        <span><span style={{color:"#4ade80",fontWeight:600}}>■</span> Correct</span>
        <span><span style={{color:"#f87171",fontWeight:600}}>■</span> Misclassified</span>
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════════════════
export default function Dashboard() {
  const {user,logout}       = useAuth();
  const navigate            = useNavigate();
  const [tab,setTab]        = useState("overview");
  const [stats,setStats]    = useState(null);
  const [alerts,setAlerts]  = useState([]);
  const [logs,setLogs]      = useState([]);
  const [metrics,setMetrics]= useState(null);
  const [loading,setLoading]= useState(true);
  const [metricsLoading,setMetricsLoading] = useState(true);
  const [attackPopup,setAttackPopup] = useState(null);
  const [wsStatus,setWsStatus] = useState("connecting"); // "connected"|"disconnected"|"connecting"
  const prevCount = useRef(0);
  const prevIds   = useRef(new Set());

  // filters (alerts tab)
  const [search,setSearch]       = useState("");
  const [sevF,setSevF]           = useState("All");
  const [dateF,setDateF]         = useState("all");

  // detect
  const [featForm,setFeatForm]   = useState({});
  const [detectRes,setDetectRes] = useState(null);
  const [detectHistory,setDetectHistory] = useState([]);
  const [detecting,setDetecting] = useState(false);
  const [detectErr,setDetectErr] = useState("");

  // shap
  const [shapId,setShapId]       = useState("");
  const [shapData,setShapData]   = useState(null);
  const [shapLoading,setShapLoading] = useState(false);
  const [shapErr,setShapErr]     = useState("");

  // csv summary
  const [csvSummary,setCsvSummary] = useState(null);
  const [csvLoading,setCsvLoading] = useState(false);

  // sim
  const [simLoading,setSimLoading] = useState("");
  const [toast,setToast]           = useState(null);

  // live capture status
  const [capture, setCapture] = useState(null);
  const [captureLoading, setCaptureLoading] = useState(false);

  const FEATURES = [
    "logon_count_day","logon_after_hours","failed_logon_count",
    "files_accessed_count","sensitive_files_count","usb_events_count",
    "email_sent_external_count","email_attachment_mb","http_upload_mb",
    "unique_systems_accessed","logon_hour_deviation","activity_duration_mins",
    "print_jobs_count","clipboard_events_count","remote_access_mins",
  ];
  const DEMO_VALS = {
    "logon_count_day":3,"logon_after_hours":0,"failed_logon_count":0,
    "files_accessed_count":25,"sensitive_files_count":1,"usb_events_count":0,
    "email_sent_external_count":2,"email_attachment_mb":0.5,"http_upload_mb":10,
    "unique_systems_accessed":2,"logon_hour_deviation":0.5,"activity_duration_mins":420,
    "print_jobs_count":1,"clipboard_events_count":5,"remote_access_mins":0,
  };

  const showToast=(msg,type="success")=>{ setToast({msg,type}); setTimeout(()=>setToast(null),3500); };

  const fetchCapture = useCallback(async () => {
    try {
      const res = await API.get("/capture/status");
      setCapture(res.data);
    } catch (e) {
      console.error("Failed to fetch capture status", e);
    }
  }, []);

  const handleToggleCapture = async () => {
    if (!capture) return;
    setCaptureLoading(true);
    try {
      const action = capture.running ? "stop" : "start";
      const res = await API.post(`/capture/${action}`);
      showToast(res.data.message);
      fetchCapture();
    } catch (e) {
      showToast(e.response?.data?.detail || "Action failed", "error");
    } finally {
      setCaptureLoading(false);
    }
  };

  const fetchAll = useCallback(async()=>{
    try {
      const [sRes,aRes] = await Promise.all([API.get("/data/stats"), API.get("/data/alerts?limit=200")]);
      setStats(sRes.data);
      const newAlerts = aRes.data;
      // detect new attacks for popup
      newAlerts.forEach(a=>{
        if(!prevIds.current.has(a.id) && a.attack_type!=="BENIGN" && prevCount.current>0) {
          setAttackPopup({...a, alert_id:a.id});
        }
        prevIds.current.add(a.id);
      });
      prevCount.current = newAlerts.length;
      setAlerts(newAlerts);
      
      // Fetch live sniffer status
      fetchCapture();
      
      if(user?.role==="admin"){ const lRes=await API.get("/data/logs?limit=50"); setLogs(lRes.data); }
    } catch(e){ console.error(e); }
    finally{ setLoading(false); }
  },[user, fetchCapture]);

  const fetchMetrics = useCallback(async()=>{
    try{ const r=await API.get("/data/metrics"); setMetrics(r.data); }
    catch(e){ console.error(e); }
    finally{ setMetricsLoading(false); }
  },[]);

  // ── WebSocket: open once on mount, tear down on unmount ──────────────────
  useEffect(() => {
    const token = localStorage.getItem("token") || "";
    connectWS(token);

    const listenerId = addWSListener((msg) => {
      if (msg.type === "_connected")    { setWsStatus("connected");    return; }
      if (msg.type === "_disconnected") { setWsStatus("disconnected"); return; }

      if (msg.type === "new_alert") {
        const p = msg.payload;
        // Deduplicate by alert id
        if (prevIds.current.has(p.id)) return;
        prevIds.current.add(p.id);

        // Show attack popup for non-BENIGN alerts
        if (p.attack_type !== "BENIGN") {
          setAttackPopup({ ...p, alert_id: p.id });
        }

        // Prepend to alerts list (keep max 200)
        setAlerts(prev => [p, ...prev].slice(0, 200));

        // Increment stats counters live without re-fetching
        setStats(prev => {
          if (!prev) return prev;
          const sev = p.severity || "Low";
          return {
            ...prev,
            total_alerts: (prev.total_alerts || 0) + 1,
            total_anomalies: p.is_anomaly
              ? (prev.total_anomalies || 0) + 1
              : prev.total_anomalies,
            severity_counts: {
              ...prev.severity_counts,
              [sev]: ((prev.severity_counts || {})[sev] || 0) + 1,
            },
            attack_distribution: {
              ...prev.attack_distribution,
              [p.attack_type]: ((prev.attack_distribution || {})[p.attack_type] || 0) + 1,
            },
            anomaly_scores: [...(prev.anomaly_scores || []), p.anomaly_score].slice(-200),
            risk_scores:    [...(prev.risk_scores    || []), p.risk_score   ].slice(-200),
          };
        });
      }
    });

    return () => {
      removeWSListener(listenerId);
      disconnectWS();
    };
  // The empty dep array is intentional: WS opens once on mount using the token from localStorage.
  // eslint-disable-next-line
  }, []);

  // ── REST polling (30s) for initial load + catch-up ────────────────────────
  useEffect(()=>{ fetchAll(); fetchMetrics(); const t=setInterval(fetchAll,30000); return()=>clearInterval(t); },[fetchAll,fetchMetrics]);

  // filtered alerts
  const filteredAlerts = alerts.filter(a=>{
    if(sevF!=="All"&&a.severity!==sevF) return false;
    if(search&&!a.attack_type.toLowerCase().includes(search.toLowerCase())&&
       !String(a.id).includes(search)) return false;
    if(dateF!=="all"){
      const cut=new Date();
      if(dateF==="today") cut.setHours(0,0,0,0);
      else if(dateF==="7d") cut.setDate(cut.getDate()-7);
      else if(dateF==="30d") cut.setDate(cut.getDate()-30);
      if(new Date(a.timestamp)<cut) return false;
    }
    return true;
  });

  // export CSV
  const exportCSV=(data,filename)=>{
    const header = "ID,Timestamp,Attack Type,Anomaly Score,Risk Score,Severity";
    const rows   = data.map(a=>`${a.id},"${fmt(a.timestamp)}",${a.attack_type},${a.anomaly_score?.toFixed(4)},${a.risk_score?.toFixed(1)},${a.severity}`);
    const blob   = new Blob([[header,...rows].join("\n")],{type:"text/csv"});
    const url    = URL.createObjectURL(blob);
    const link   = document.createElement("a");
    link.href=url; link.download=filename; link.click(); URL.revokeObjectURL(url);
    showToast("CSV exported successfully");
  };

  // simulate
  const simulate=async(type)=>{
    setSimLoading(type);
    try{
      const {data}=await API.post(type==="dos"?"/detect/simulate-dos":"/detect/simulate-anomaly");
      showToast(`${type==="dos"?"DoS":"Anomaly"} simulated → ${data.attack_type} (Risk: ${data.risk_score})`);
      if(data.attack_type!=="BENIGN") setAttackPopup(data);
      fetchAll();
    } catch{ showToast("Simulation failed","error"); }
    finally{ setSimLoading(""); }
  };

  // detect
  const runDetect=async()=>{
    setDetecting(true); setDetectErr("");
    try{
      const features={};
      FEATURES.forEach(f=>{ features[f]=parseFloat(featForm[f])||0; });
      const {data}=await API.post("/detect/",{features});
      setDetectRes(data);
      setDetectHistory(h=>[{...data,ts:new Date().toISOString(),inputFeatures:features},...h].slice(0,20));
      if(data.attack_type!=="BENIGN") setAttackPopup(data);
      fetchAll();
      showToast(`Detection complete — ${data.attack_type}`);
    } catch(e){ setDetectErr(e.response?.data?.detail||"Detection failed"); }
    finally{ setDetecting(false); }
  };

  // shap
  const loadShap=async(id)=>{
    if(!id) return;
    setShapLoading(true); setShapErr("");
    try{ const {data}=await API.get(`/explain/${id}`); setShapData(data); }
    catch{ setShapErr("Could not load SHAP explanation for this alert."); }
    finally{ setShapLoading(false); }
  };

  // export detection history
  const exportHistory=()=>{
    if(!detectHistory.length){ showToast("No history to export","error"); return; }
    const header="Alert ID,Timestamp,Attack Type,Risk Score,Severity,Is Anomaly";
    const rows=detectHistory.map(d=>`${d.alert_id},"${fmt(d.ts||d.timestamp)}",${d.attack_type},${d.risk_score?.toFixed(1)},${d.severity},${d.is_anomaly}`);
    const blob=new Blob([[header,...rows].join("\n")],{type:"text/csv"});
    const url=URL.createObjectURL(blob); const link=document.createElement("a");
    link.href=url; link.download="detection_history.csv"; link.click(); URL.revokeObjectURL(url);
    showToast("Detection history exported");
  };

  // chart data
  const anomalyLine = stats ? {
    labels:stats.anomaly_scores.map((_,i)=>i+1),
    datasets:[
      {label:"Anomaly Score",data:stats.anomaly_scores,borderColor:T.blue,backgroundColor:"rgba(56,189,248,0.08)",borderWidth:2,pointRadius:2,tension:0.3,fill:true},
      {label:"Threshold",data:stats.anomaly_scores.map(()=>-0.1),borderColor:T.red,borderDash:[5,4],borderWidth:1.5,pointRadius:0,fill:false},
    ],
  } : null;

  const attackPie = stats ? {
    labels:Object.keys(stats.attack_distribution),
    datasets:[{data:Object.values(stats.attack_distribution),backgroundColor:PIE_COLORS,borderColor:T.bg,borderWidth:2}],
  } : null;

  const attackVsNormal = stats ? {
    labels:["Normal (BENIGN)","Attacks"],
    datasets:[{data:[stats.attack_distribution?.BENIGN||0,
      Object.entries(stats.attack_distribution||{}).filter(([k])=>k!=="BENIGN").reduce((a,[,v])=>a+v,0)],
      backgroundColor:["rgba(74,222,128,0.8)","rgba(248,113,113,0.8)"],borderColor:T.bg,borderWidth:2}],
  } : null;

  const topAttacks = stats ? (()=>{
    const d=Object.entries(stats.attack_distribution||{}).filter(([k])=>k!=="BENIGN").sort((a,b)=>b[1]-a[1]).slice(0,6);
    return {labels:d.map(([k])=>k),datasets:[{label:"Count",data:d.map(([,v])=>v),
      backgroundColor:"rgba(248,113,113,0.75)",borderRadius:5}]};
  })() : null;

  const timeline = stats ? {
    labels:stats.hourly_timeline.map(h=>h.hour),
    datasets:[{label:"Alerts",data:stats.hourly_timeline.map(h=>h.count),
      borderColor:T.indigo,backgroundColor:"rgba(129,140,248,0.12)",
      borderWidth:2,tension:0.4,fill:true,pointRadius:3}],
  } : null;

  const riskBar = stats ? {
    labels:stats.risk_scores.slice(-20).map((_,i)=>`#${i+1}`),
    datasets:[{label:"Risk Score",data:stats.risk_scores.slice(-20),
      backgroundColor:stats.risk_scores.slice(-20).map(r=>r>=70?"rgba(248,113,113,0.75)":r>=40?"rgba(251,191,36,0.75)":"rgba(74,222,128,0.7)"),borderRadius:4}],
  } : null;

  const featImp = stats ? {
    labels:Object.keys(stats.feature_importance||{}).slice(0,10),
    datasets:[{label:"Importance",data:Object.values(stats.feature_importance||{}).slice(0,10),
      backgroundColor:"rgba(129,140,248,0.72)",borderRadius:4}],
  } : null;

  const shapBar = shapData?.top_features?.length ? {
    labels:shapData.top_features.map(f=>f.feature),
    datasets:[{label:"SHAP Value",data:shapData.top_features.map(f=>f.shap),
      backgroundColor:shapData.top_features.map(f=>f.shap>=0?"rgba(248,113,113,0.75)":"rgba(56,189,248,0.75)"),borderRadius:4}],
  } : null;

  const tabs=[
    {id:"overview",  label:"📊 Overview"},
    {id:"model",     label:"🤖 Model Performance"},
    {id:"analytics", label:"📈 SOC Analytics"},
    {id:"alerts",    label:"🚨 Alerts"},
    {id:"detect",    label:"🔍 Detect"},
    {id:"history",   label:"📝 History"},
    {id:"shap",      label:"🔬 Explain"},
    {id:"csv",       label:"📁 Bulk Upload"},
    ...(user?.role==="admin"?[{id:"logs",label:"📋 Logs"}]:[]),
  ];

  const totalAttacks = alerts.filter(a=>a.attack_type!=="BENIGN").length;
  const totalNormal  = alerts.filter(a=>a.attack_type==="BENIGN").length;
  const attackRate   = alerts.length>0 ? ((totalAttacks/alerts.length)*100).toFixed(1) : "0.0";

  // css shorthand
  const S={
    pageTitle:{color:T.blue,fontSize:17,fontWeight:700,letterSpacing:"-0.3px",marginBottom:18},
    table:{width:"100%",borderCollapse:"collapse",fontSize:12},
    th:{textAlign:"left",padding:"8px 12px",color:T.muted,borderBottom:`1px solid ${T.border}`,fontSize:11,fontWeight:600,textTransform:"uppercase",letterSpacing:"0.3px"},
    td:{padding:"10px 12px",borderBottom:`1px solid rgba(255,255,255,0.04)`,color:T.text},
    tr:{transition:"background .1s"},
    fi:{background:T.surface,border:`1px solid ${T.border}`,borderRadius:8,padding:"7px 10px",color:T.text,fontSize:12,outline:"none",width:"100%"},
    fsel:{background:T.surface,border:`1px solid ${T.border}`,borderRadius:8,padding:"8px 12px",color:T.text,fontSize:13,outline:"none"},
  };

  return (
    <div style={{display:"flex",minHeight:"100vh",background:T.bg}}>
      {/* CSS for shrink animation */}
      <style>{`@keyframes shrink{from{width:100%}to{width:0%}}`}</style>

      {/* Attack Popup */}
      {attackPopup && <AttackPopup alert={attackPopup} onClose={()=>setAttackPopup(null)}/>}

      {/* Toast */}
      {toast&&<div style={{position:"fixed",top:20,right:20,zIndex:9000,padding:"10px 20px",
        borderRadius:8,fontWeight:600,fontSize:13,
        color:toast.type==="error"?"#fff":"#0f172a",
        background:toast.type==="error"?"#ef4444":"#4ade80",
        boxShadow:"0 4px 20px rgba(0,0,0,0.4)",animation:"fadeIn 0.2s ease"}}>{toast.msg}</div>}

      {/* Sidebar */}
      <aside style={{width:210,background:T.surface,borderRight:`1px solid ${T.border}`,
        display:"flex",flexDirection:"column",position:"sticky",top:0,height:"100vh",overflowY:"auto",flexShrink:0}}>
        <div style={{padding:"18px 14px 14px",borderBottom:`1px solid ${T.border}`,textAlign:"center"}}>
          <div style={{fontSize:28}}>🛡️</div>
          <div style={{color:T.blue,fontWeight:700,fontSize:13,marginTop:5}}>Hybrid IDS</div>
          <div style={{color:T.muted,fontSize:9,marginTop:2}}>XGBoost + Isolation Forest</div>
          <div style={{display:"flex",alignItems:"center",justifyContent:"center",gap:5,marginTop:7}}>
            <span style={{
              width:7,height:7,borderRadius:"50%",flexShrink:0,
              background: wsStatus==="connected" ? "#4ade80" : wsStatus==="connecting" ? "#fbbf24" : "#f87171",
              boxShadow: wsStatus==="connected" ? "0 0 6px #4ade80" : "none",
            }}/>
            <span style={{fontSize:9,color:T.muted,letterSpacing:"0.3px"}}>
              {wsStatus==="connected"?"Live":wsStatus==="connecting"?"Connecting…":"Disconnected"}
            </span>
          </div>
        </div>
        <nav style={{flex:1,paddingTop:6}}>
          {tabs.map(t=>(
            <div key={t.id} onClick={()=>setTab(t.id)}
              style={{padding:"9px 14px",cursor:"pointer",fontSize:12,fontWeight:500,
                color:tab===t.id?T.blue:T.sub,
                background:tab===t.id?"rgba(56,189,248,0.08)":"transparent",
                borderLeft:`3px solid ${tab===t.id?T.blue:"transparent"}`,transition:"all .15s"}}>
              {t.label}
            </div>
          ))}
        </nav>
        <div style={{padding:10,borderTop:`1px solid ${T.border}`}}>
          <div style={{color:T.muted,fontSize:9,letterSpacing:"0.5px",marginBottom:6,fontWeight:600}}>SIMULATE</div>
          <button onClick={()=>simulate("dos")} disabled={!!simLoading}
            style={{width:"100%",padding:"7px 0",background:"transparent",border:`1px solid ${T.blue}`,
              borderRadius:7,color:T.blue,cursor:"pointer",fontSize:11,fontWeight:500,marginBottom:5}}>
            {simLoading==="dos"?"⏳…":"📤 Simulate Exfil"}
          </button>
          <button onClick={()=>simulate("anomaly")} disabled={!!simLoading}
            style={{width:"100%",padding:"7px 0",background:"transparent",border:`1px solid ${T.orange}`,
              borderRadius:7,color:T.orange,cursor:"pointer",fontSize:11,fontWeight:500}}>
            {simLoading==="anomaly"?"⏳…":"🔓 Simulate Priv Abuse"}
          </button>
        </div>
        <div style={{padding:12,borderTop:`1px solid ${T.border}`}}>
          <div style={{color:T.text,fontSize:12,fontWeight:500}}>👤 {user?.username}</div>
          <span style={{background:"rgba(56,189,248,0.12)",color:T.blue,padding:"1px 8px",
            borderRadius:10,fontSize:10,fontWeight:600}}>{user?.role?.toUpperCase()}</span>
          <button onClick={()=>{logout();navigate("/login");}}
            style={{marginTop:8,width:"100%",padding:"7px 0",background:"transparent",
              border:"1px solid rgba(248,113,113,0.4)",borderRadius:7,color:T.red,
              cursor:"pointer",fontSize:11,fontWeight:500}}>Logout</button>
        </div>
      </aside>

      {/* Main */}
      <main style={{flex:1,padding:"22px 26px",overflowY:"auto",maxWidth:"calc(100vw - 210px)"}}>

        {/* ── OVERVIEW ──────────────────────────────────────────────────────── */}
        {tab==="overview"&&(
          <div style={{animation:"fadeIn 0.2s ease"}}>
            <h2 style={S.pageTitle}>System Overview</h2>
            {/* Threat level & Live Sniffer Grid */}
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:14,marginBottom:14}}>
              {stats&&(()=>{
                const hp=(stats.severity_counts?.High||0)/Math.max(stats.total_alerts,1);
                const lvl=hp>0.3?"CRITICAL":hp>0.1?"WARNING":"SAFE";
                const cfg={CRITICAL:{color:"#f87171",bg:"rgba(248,113,113,0.08)",icon:"🔴"},
                           WARNING:{color:"#fbbf24",bg:"rgba(251,191,36,0.08)",icon:"🟡"},
                           SAFE:{color:"#4ade80",bg:"rgba(74,222,128,0.08)",icon:"🟢"}}[lvl];
                return <div style={{background:cfg.bg,border:`1px solid ${cfg.color}33`,borderRadius:10,
                  padding:"12px 18px",display:"flex",alignItems:"center",gap:12,height:"100%"}}>
                  <span style={{fontSize:24}}>{cfg.icon}</span>
                  <div>
                    <div style={{color:cfg.color,fontWeight:700,fontSize:14}}>Threat Level: {lvl}</div>
                    <div style={{color:T.muted,fontSize:12,marginTop:2}}>{stats.severity_counts?.High||0} high-severity out of {stats.total_alerts} total alerts</div>
                  </div>
                </div>;
              })()}

              {capture && (
                <div style={{
                  background: capture.running ? "rgba(74,222,128,0.05)" : "rgba(248,113,113,0.05)",
                  border: `1px solid ${capture.running ? "#4ade8033" : "#f8717133"}`,
                  borderRadius: 10, padding: "12px 18px", display: "flex", justifyContent: "space-between", alignItems: "center", height: "100%"
                }}>
                  <div style={{display:"flex",alignItems:"center",gap:12}}>
                    <span style={{
                      width: 10, height: 10, borderRadius: "50%",
                      background: capture.running ? "#4ade80" : "#f87171",
                      boxShadow: capture.running ? "0 0 8px #4ade80" : "none",
                      animation: capture.running ? "pulse 1.5s infinite" : "none"
                    }} />
                    <div>
                      <div style={{color: capture.running ? "#4ade80" : "#f87171", fontWeight: 700, fontSize: 14}}>
                        Live Packet Sniffer: {capture.running ? "Active" : "Stopped"}
                      </div>
                      <div style={{color: T.muted, fontSize: 12, marginTop: 2}}>
                        Interface: <span style={{color:T.blue,fontWeight:600}}>{capture.interface || "auto"}</span> | Packets Processed: <span style={{color:T.indigo,fontWeight:600}}>{capture.packets_seen?.toLocaleString()}</span>
                      </div>
                    </div>
                  </div>
                  {user?.role === "admin" && (
                    <button
                      onClick={handleToggleCapture}
                      disabled={captureLoading}
                      style={{
                        padding: "6px 12px", borderRadius: 6, fontSize: 11, fontWeight: 600, cursor: "pointer",
                        background: capture.running ? "rgba(248,113,113,0.12)" : "rgba(74,222,128,0.12)",
                        color: capture.running ? "#f87171" : "#4ade80",
                        border: `1px solid ${capture.running ? "rgba(248,113,113,0.3)" : "rgba(74,222,128,0.3)"}`,
                        transition: "all 0.15s"
                      }}
                    >
                      {captureLoading ? "⏳" : capture.running ? "Stop Sniffer" : "Start Sniffer"}
                    </button>
                  )}
                </div>
              )}
            </div>
            <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:12,marginBottom:14}}>
              <StatCard icon="🚨" label="Total Alerts"   value={stats?.total_alerts?.toLocaleString()}   accent={T.blue}   loading={loading}/>
              <StatCard icon="⚠️" label="Anomalies"      value={stats?.total_anomalies?.toLocaleString()} accent={T.orange} loading={loading} sub="Isolation Forest"/>
              <StatCard icon="🔴" label="High Severity"  value={stats?.severity_counts?.High?.toLocaleString()} accent={T.red} loading={loading}/>
              <StatCard icon="✅" label="Normal Traffic" value={stats?.attack_distribution?.BENIGN?.toLocaleString()} accent={T.green} loading={loading}/>
            </div>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:14,marginBottom:14}}>
              <Card title="📈 Anomaly Score Over Time" height={200}>
                {loading?<Spinner/>:anomalyLine
                  ?<Line data={anomalyLine} options={{...cOpts(),plugins:{...cOpts().plugins,legend:{display:true,labels:{color:T.muted,font:{size:10},boxWidth:10}}}}}/>
                  :<Empty icon="📉" msg="No data yet — run a simulation"/>}
              </Card>
              <Card title="🥧 Attack Distribution" height={200}>
                {loading?<Spinner/>:attackPie
                  ?<Doughnut data={attackPie} options={{responsive:true,maintainAspectRatio:false,
                    plugins:{legend:{display:true,position:"right",labels:{color:T.muted,font:{size:10},boxWidth:10}},
                    tooltip:{backgroundColor:T.surface,titleColor:T.blue,bodyColor:T.text,borderColor:T.border,borderWidth:1}}}}/>
                  :<Empty icon="🥧" msg="No data yet"/>}
              </Card>
            </div>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:14,marginBottom:14}}>
              <Card title="📉 Alerts Timeline — 24h" height={170}>
                {loading?<Spinner/>:timeline?<Line data={timeline} options={cOpts()}/>:<Empty icon="📉" msg="No data yet"/>}
              </Card>
              <Card title="🔒 Severity Breakdown" height={170}>
                {loading?<Spinner/>:stats?.severity_counts
                  ?<Doughnut data={{labels:["Low","Medium","High"],datasets:[{data:[stats.severity_counts.Low||0,stats.severity_counts.Medium||0,stats.severity_counts.High||0],
                    backgroundColor:["rgba(74,222,128,0.8)","rgba(251,191,36,0.8)","rgba(248,113,113,0.8)"],borderColor:T.bg,borderWidth:2}]}}
                    options={{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:true,position:"right",labels:{color:T.muted,font:{size:10},boxWidth:10}},
                    tooltip:{backgroundColor:T.surface,titleColor:T.blue,bodyColor:T.text,borderColor:T.border,borderWidth:1}}}}/>
                  :<Empty icon="🔒" msg="No data yet"/>}
              </Card>
            </div>
            <Card title="🚨 Latest Alerts">
              {loading?<Spinner/>:alerts.length===0?<Empty icon="🚨" msg="No alerts yet. Behaviour simulation starting…"/>
                :<table style={S.table}><thead><tr>{["Time","Employee","Dept","Threat Type","Risk","Severity"].map(h=><th key={h} style={S.th}>{h}</th>)}</tr></thead>
                <tbody>{alerts.slice(0,8).map(a=>(
                  <tr key={a.id} style={{...S.tr,background:a.attack_type!=="BENIGN"&&a.severity==="High"?"rgba(248,113,113,0.04)":"transparent"}}>
                    <td style={S.td}>{fmtT(a.timestamp)}</td>
                    <td style={{...S.td,fontWeight:600,color:T.text}}>{a.employee_name||"—"}</td>
                    <td style={{...S.td,color:T.muted,fontSize:11}}>{a.department||"—"}</td>
                    <td style={{...S.td,color:a.attack_type==="BENIGN"?T.green:T.red,fontWeight:600}}>{a.attack_type}</td>
                    <td style={S.td}>{a.risk_score?.toFixed(1)}</td>
                    <td style={S.td}>{sevBadge(a.severity)}</td>
                  </tr>
                ))}</tbody></table>}
            </Card>

            {stats?.top_risky_employees?.length>0&&(
              <Card title="🔥 Top Risk Employees">
                <table style={S.table}><thead><tr>
                  {["Rank","Employee","Department","Avg Risk","Incidents"].map(h=><th key={h} style={S.th}>{h}</th>)}
                </tr></thead>
                <tbody>{stats.top_risky_employees.map((e,i)=>(
                  <tr key={e.employee_id} style={{...S.tr,background:i===0?"rgba(248,113,113,0.06)":"transparent"}}>
                    <td style={{...S.td,color:i===0?T.red:i===1?"#fb923c":i===2?T.yellow:T.muted,fontWeight:700,fontSize:13}}>
                      {i===0?"🥇":i===1?"🥈":i===2?"🥉":`#${i+1}`}
                    </td>
                    <td style={{...S.td,fontWeight:600,color:T.text}}>{e.employee_name}</td>
                    <td style={{...S.td,color:T.muted,fontSize:11}}>{e.department}</td>
                    <td style={S.td}>
                      <span style={{color:e.avg_risk>=70?T.red:e.avg_risk>=40?T.yellow:T.green,fontWeight:700}}>{e.avg_risk}</span>
                      <span style={{color:T.muted,fontSize:10}}>/100</span>
                    </td>
                    <td style={{...S.td,color:T.orange,fontWeight:600}}>{e.incident_count}</td>
                  </tr>
                ))}</tbody></table>
              </Card>
            )}
          </div>
        )}

        {/* ── MODEL PERFORMANCE ─────────────────────────────────────────────── */}
        {tab==="model"&&(
          <div style={{animation:"fadeIn 0.2s ease"}}>
            <h2 style={S.pageTitle}>Model Performance Dashboard</h2>
            {metricsLoading?<Spinner/>:!metrics?<Empty icon="🤖" msg="Metrics unavailable"/>:(
              <div>
                {/* XGBoost */}
                <Card title="🌲 XGBoost Classifier — Multi-class Attack Detection">
                  <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:24,marginBottom:20}}>
                    <MetricGauge label="Accuracy"  value={metrics.xgboost.accuracy}  color={T.blue}/>
                    <MetricGauge label="Precision" value={metrics.xgboost.precision} color={T.green}/>
                    <MetricGauge label="Recall"    value={metrics.xgboost.recall}    color={T.yellow}/>
                    <MetricGauge label="F1 Score"  value={metrics.xgboost.f1}        color={T.purple}/>
                  </div>
                  <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:14}}>
                    <div style={{background:T.bg,borderRadius:10,padding:14}}>
                      <div style={{color:T.sub,fontSize:12,marginBottom:12,fontWeight:600}}>Performance Metrics</div>
                      {[["Accuracy",metrics.xgboost.accuracy,T.blue],
                        ["Precision",metrics.xgboost.precision,T.green],
                        ["Recall",metrics.xgboost.recall,T.yellow],
                        ["F1 Score",metrics.xgboost.f1,T.purple]].map(([l,v,c])=>(
                        <div key={l} style={{marginBottom:10}}>
                          <div style={{display:"flex",justifyContent:"space-between",marginBottom:3}}>
                            <span style={{color:T.sub,fontSize:12}}>{l}</span>
                            <span style={{color:c,fontWeight:700,fontSize:12}}>{v}%</span>
                          </div>
                          <div style={{height:6,background:T.border,borderRadius:3,overflow:"hidden"}}>
                            <div style={{height:"100%",width:`${v}%`,background:c,borderRadius:3,transition:"width 0.8s ease"}}/>
                          </div>
                        </div>
                      ))}
                      <div style={{marginTop:14,padding:"10px 12px",background:"rgba(56,189,248,0.06)",borderRadius:8,border:`1px solid rgba(56,189,248,0.15)`}}>
                        <div style={{color:T.muted,fontSize:11}}>💡 High accuracy on BENIGN class. Attack classes show class-imbalance challenges common in IDS datasets.</div>
                      </div>
                    </div>
                    <div style={{background:T.bg,borderRadius:10,padding:14}}>
                      <ConfusionMatrix matrix={metrics.xgboost.confusion_matrix} classes={metrics.xgboost.classes} title="XGBoost Confusion Matrix"/>
                    </div>
                  </div>
                </Card>

                {/* Isolation Forest */}
                <Card title="🌲 Isolation Forest — Anomaly Detection (Binary)">
                  <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:24,marginBottom:20}}>
                    <MetricGauge label="Accuracy"  value={metrics.isolation_forest.accuracy}  color={T.blue}/>
                    <MetricGauge label="Precision" value={metrics.isolation_forest.precision} color={T.green}/>
                    <MetricGauge label="Recall"    value={metrics.isolation_forest.recall}    color={T.yellow}/>
                    <MetricGauge label="F1 Score"  value={metrics.isolation_forest.f1}        color={T.purple}/>
                  </div>
                  <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:14}}>
                    <div style={{background:T.bg,borderRadius:10,padding:14}}>
                      {[["Accuracy",metrics.isolation_forest.accuracy,T.blue],
                        ["Precision",metrics.isolation_forest.precision,T.green],
                        ["Recall",metrics.isolation_forest.recall,T.yellow],
                        ["F1 Score",metrics.isolation_forest.f1,T.purple]].map(([l,v,c])=>(
                        <div key={l} style={{marginBottom:10}}>
                          <div style={{display:"flex",justifyContent:"space-between",marginBottom:3}}>
                            <span style={{color:T.sub,fontSize:12}}>{l}</span>
                            <span style={{color:c,fontWeight:700,fontSize:12}}>{v}%</span>
                          </div>
                          <div style={{height:6,background:T.border,borderRadius:3,overflow:"hidden"}}>
                            <div style={{height:"100%",width:`${v}%`,background:c,borderRadius:3,transition:"width 0.8s ease"}}/>
                          </div>
                        </div>
                      ))}
                      <div style={{marginTop:14,padding:"10px 12px",background:"rgba(56,189,248,0.06)",borderRadius:8,border:`1px solid rgba(56,189,248,0.15)`}}>
                        <div style={{color:T.muted,fontSize:11}}>💡 High precision (91.8%) means few false positives. Lower recall is expected for unsupervised anomaly detection.</div>
                      </div>
                    </div>
                    <div style={{background:T.bg,borderRadius:10,padding:14}}>
                      <ConfusionMatrix matrix={metrics.isolation_forest.confusion_matrix} classes={metrics.isolation_forest.classes} title="Isolation Forest Confusion Matrix"/>
                    </div>
                  </div>
                </Card>

                {/* Dataset info */}
                <Card title="📊 Training Dataset Summary">
                  <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:12}}>
                    {[["Total Samples","40,000",T.blue],["Training Set","27,200 (68%)",T.green],
                      ["Test Set","8,000 (20%)",T.yellow],["Attack Classes","4 + BENIGN",T.purple]].map(([l,v,c])=>(
                      <div key={l} style={{background:T.bg,borderRadius:8,padding:"12px 14px",borderLeft:`3px solid ${c}`}}>
                        <div style={{color:T.muted,fontSize:11}}>{l}</div>
                        <div style={{color:c,fontWeight:700,fontSize:18,marginTop:4}}>{v}</div>
                      </div>
                    ))}
                  </div>
                  <div style={{marginTop:12,padding:"10px 14px",background:"rgba(129,140,248,0.06)",borderRadius:8,border:`1px solid rgba(129,140,248,0.15)`}}>
                    <div style={{color:T.sub,fontSize:12}}>Dataset: Synthetic CERT/UBA (insider threat) · Features: 15 user-behaviour features · Preprocessing: SMOTE oversampling + StandardScaler + IF threshold tuning</div>
                  </div>
                </Card>
              </div>
            )}
          </div>
        )}

        {/* ── SOC ANALYTICS ─────────────────────────────────────────────────── */}
        {tab==="analytics"&&(
          <div style={{animation:"fadeIn 0.2s ease"}}>
            <h2 style={S.pageTitle}>SOC Analytics Dashboard</h2>
            <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:12,marginBottom:14}}>
              <StatCard icon="📦" label="Total Records" value={alerts.length.toLocaleString()} accent={T.blue} loading={loading}/>
              <StatCard icon="💣" label="Attacks" value={totalAttacks.toLocaleString()} accent={T.red} loading={loading}/>
              <StatCard icon="✅" label="Normal" value={totalNormal.toLocaleString()} accent={T.green} loading={loading}/>
              <StatCard icon="📊" label="Attack Rate" value={`${attackRate}%`} accent={T.orange} loading={loading}/>
            </div>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:14,marginBottom:14}}>
              <Card title="⚔️ Attack vs Normal Traffic" height={220}>
                {loading?<Spinner/>:attackVsNormal
                  ?<Doughnut data={attackVsNormal} options={{responsive:true,maintainAspectRatio:false,
                    plugins:{legend:{display:true,position:"right",labels:{color:T.muted,font:{size:11},boxWidth:12}},
                    tooltip:{backgroundColor:T.surface,titleColor:T.blue,bodyColor:T.text,borderColor:T.border,borderWidth:1}}}}/>
                  :<Empty icon="⚔️" msg="No data yet"/>}
              </Card>
              <Card title="🏆 Top Attack Types" height={220}>
                {loading?<Spinner/>:topAttacks
                  ?<Bar data={topAttacks} options={cOpts({indexAxis:"y",plugins:{...cOpts().plugins,legend:{display:false}}})}/>
                  :<Empty icon="🏆" msg="No attacks detected yet"/>}
              </Card>
            </div>
            <Card title="📈 Attack Trends Over Time (Hourly)" height={200}>
              {loading?<Spinner/>:timeline?<Line data={timeline} options={cOpts({plugins:{...cOpts().plugins,legend:{display:false}}})}/>:<Empty icon="📈" msg="No data yet"/>}
            </Card>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:14}}>
              <Card title="🏢 Incidents by Department" height={200}>
                {loading?<Spinner/>:stats?.department_breakdown&&Object.keys(stats.department_breakdown).length>0
                  ?<Bar data={{
                      labels:Object.keys(stats.department_breakdown),
                      datasets:[{label:"Incidents",data:Object.values(stats.department_breakdown),
                        backgroundColor:"rgba(251,191,36,0.75)",borderRadius:5}]
                    }} options={cOpts({indexAxis:"y",plugins:{...cOpts().plugins,legend:{display:false}}})}/>
                  :<Empty icon="🏢" msg="No department data yet"/>}
              </Card>
              <Card title="🔥 Risk Score Distribution" height={200}>
                {loading?<Spinner/>:riskBar?<Bar data={riskBar} options={cOpts({scales:{...cOpts().scales,y:{...cOpts().scales.y,max:100}}})}/>:<Empty icon="🔥" msg="No data yet"/>}
              </Card>
            </div>
            <Card title="📊 Feature Importance (XGBoost — Behaviour Signals)" height={200}>
              {loading?<Spinner/>:featImp
                ?<Bar data={featImp} options={cOpts({indexAxis:"y",plugins:{...cOpts().plugins,legend:{display:false}},
                  scales:{x:{ticks:{color:T.muted,font:{size:9}},grid:{color:"rgba(255,255,255,0.04)"}},
                          y:{ticks:{color:T.muted,font:{size:9}},grid:{color:"rgba(255,255,255,0.04)"}}}})}/>
                :<Empty icon="📊" msg="No data yet"/>}
            </Card>
          </div>
        )}

        {/* ── ALERTS ────────────────────────────────────────────────────────── */}
        {tab==="alerts"&&(
          <div style={{animation:"fadeIn 0.2s ease"}}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:14}}>
              <h2 style={{...S.pageTitle,marginBottom:0}}>All Alerts</h2>
              <button onClick={()=>exportCSV(filteredAlerts,"ids_alerts.csv")}
                style={{padding:"8px 16px",background:"rgba(74,222,128,0.1)",border:`1px solid ${T.green}`,
                  borderRadius:8,color:T.green,cursor:"pointer",fontSize:12,fontWeight:600}}>
                ⬇ Export CSV
              </button>
            </div>
            <div style={{display:"flex",gap:10,marginBottom:12,flexWrap:"wrap"}}>
              <input placeholder="Search attack type or ID…" value={search} onChange={e=>setSearch(e.target.value)}
                style={{...S.fi,flex:1,minWidth:180}}/>
              <select value={sevF} onChange={e=>setSevF(e.target.value)} style={S.fsel}>
                {["All","High","Medium","Low"].map(v=><option key={v} value={v}>{v==="All"?"All Severities":v}</option>)}
              </select>
              <select value={dateF} onChange={e=>setDateF(e.target.value)} style={S.fsel}>
                {[["all","All Time"],["today","Today"],["7d","Last 7 Days"],["30d","Last 30 Days"]].map(([v,l])=><option key={v} value={v}>{l}</option>)}
              </select>
              <span style={{color:T.muted,fontSize:12,display:"flex",alignItems:"center"}}>{filteredAlerts.length} results</span>
            </div>
            <Card title="">
              {loading?<Spinner/>:filteredAlerts.length===0?<Empty icon="🔍" msg="No alerts match your filters."/>
                :<table style={S.table}><thead><tr>{["ID","Timestamp","Employee","Department","Threat Type","Risk","Severity","Action"].map(h=><th key={h} style={S.th}>{h}</th>)}</tr></thead>
                <tbody>{filteredAlerts.map(a=>(
                  <tr key={a.id} style={{...S.tr,background:a.attack_type!=="BENIGN"&&a.severity==="High"?"rgba(248,113,113,0.05)":"transparent"}}>
                    <td style={{...S.td,color:T.muted}}>#{a.id}</td>
                    <td style={{...S.td,fontSize:11}}>{fmt(a.timestamp)}</td>
                    <td style={{...S.td,fontWeight:600,color:T.text}}>{a.employee_name||"—"}</td>
                    <td style={{...S.td,color:T.muted,fontSize:11}}>{a.department||"—"}</td>
                    <td style={{...S.td,color:a.attack_type==="BENIGN"?T.green:T.red,fontWeight:600}}>{a.attack_type}</td>
                    <td style={S.td}>{a.risk_score?.toFixed(1)}</td>
                    <td style={S.td}>{sevBadge(a.severity)}</td>
                    <td style={S.td}>
                      <button onClick={()=>{setShapId(String(a.id));loadShap(a.id);setTab("shap");}}
                        style={{background:"rgba(129,140,248,0.1)",border:"1px solid rgba(129,140,248,0.3)",
                          borderRadius:6,color:T.indigo,cursor:"pointer",padding:"4px 10px",fontSize:11,fontWeight:500}}>
                        Explain
                      </button>
                    </td>
                  </tr>
                ))}</tbody></table>}
            </Card>
          </div>
        )}

        {/* ── DETECT ────────────────────────────────────────────────────────── */}
        {tab==="detect"&&(
          <div style={{animation:"fadeIn 0.2s ease"}}>
            <h2 style={S.pageTitle}>Manual Detection — Behaviour Analysis</h2>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:14}}>
              <Card title="Input Behaviour Features">
                <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8,marginBottom:12}}>
                  {FEATURES.map(f=>(
                    <div key={f}>
                      <div style={{color:T.muted,fontSize:10,marginBottom:3}}>{f}</div>
                      <input type="number" placeholder={String(DEMO_VALS[f]||0)} value={featForm[f]??""}
                        onChange={e=>setFeatForm(p=>({...p,[f]:e.target.value}))}
                        style={{width:"100%",background:T.bg,border:`1px solid ${T.border}`,
                          borderRadius:6,padding:"6px 8px",color:T.text,fontSize:12,outline:"none"}}/>
                    </div>
                  ))}
                </div>
                {detectErr&&<div style={{color:T.red,fontSize:12,marginBottom:10}}>{detectErr}</div>}
                <div style={{display:"flex",gap:8}}>
                  <button onClick={()=>setFeatForm(DEMO_VALS)}
                    style={{flex:1,padding:"9px 0",background:"transparent",border:`1px solid ${T.border}`,
                      borderRadius:7,color:T.sub,cursor:"pointer",fontSize:12,fontWeight:500}}>
                    Load Demo
                  </button>
                  <button onClick={()=>setFeatForm({})}
                    style={{padding:"9px 14px",background:"transparent",border:`1px solid ${T.border}`,
                      borderRadius:7,color:T.muted,cursor:"pointer",fontSize:12}}>
                    Clear
                  </button>
                  <button onClick={runDetect} disabled={detecting}
                    style={{flex:2,padding:"9px 0",background:"linear-gradient(135deg,#0ea5e9,#6366f1)",
                      border:"none",borderRadius:7,color:"#fff",cursor:"pointer",fontSize:12,fontWeight:600,
                      opacity:detecting?0.7:1}}>
                    {detecting?"⏳ Detecting…":"🔍 Run Detection"}
                  </button>
                </div>
              </Card>
              <div>
                {detectRes?(
                  <Card title="Detection Result" style={{borderColor:detectRes.severity==="High"?T.red:detectRes.severity==="Medium"?T.yellow:T.green}}>
                    <div style={{display:"flex",flexDirection:"column",gap:9}}>
                      {[["Alert ID",`#${detectRes.alert_id}`],["Attack Type",detectRes.attack_type],
                        ["Anomaly Score",detectRes.anomaly_score?.toFixed(4)],
                        ["Risk Score",`${detectRes.risk_score?.toFixed(1)} / 100`],
                        ["Is Anomaly",detectRes.is_anomaly?"Yes ⚠️":"No ✅"]].map(([k,v])=>(
                        <div key={k} style={{display:"flex",justifyContent:"space-between",borderBottom:`1px solid ${T.border}`,paddingBottom:8}}>
                          <span style={{color:T.muted,fontSize:12}}>{k}</span>
                          <span style={{color:k==="Attack Type"?(detectRes.attack_type==="BENIGN"?T.green:T.red):T.text,fontWeight:600,fontSize:13}}>{v}</span>
                        </div>
                      ))}
                      <div style={{display:"flex",justifyContent:"space-between"}}>
                        <span style={{color:T.muted,fontSize:12}}>Severity</span>
                        {sevBadge(detectRes.severity)}
                      </div>
                      <button onClick={()=>{setShapId(String(detectRes.alert_id));loadShap(detectRes.alert_id);setTab("shap");}}
                        style={{marginTop:4,padding:"9px 0",background:"rgba(129,140,248,0.1)",
                          border:`1px solid rgba(129,140,248,0.3)`,borderRadius:7,color:T.indigo,
                          cursor:"pointer",fontSize:12,fontWeight:600}}>
                        🔬 View SHAP Explanation
                      </button>
                    </div>
                  </Card>
                ):<Card title=""><Empty icon="🔍" msg="Fill in features and click Run Detection"/></Card>}
              </div>
            </div>
          </div>
        )}

        {/* ── PREDICTION HISTORY ────────────────────────────────────────────── */}
        {tab==="history"&&(
          <div style={{animation:"fadeIn 0.2s ease"}}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:14}}>
              <h2 style={{...S.pageTitle,marginBottom:0}}>Prediction History</h2>
              <button onClick={exportHistory}
                style={{padding:"8px 16px",background:"rgba(74,222,128,0.1)",border:`1px solid ${T.green}`,
                  borderRadius:8,color:T.green,cursor:"pointer",fontSize:12,fontWeight:600}}>
                ⬇ Export CSV
              </button>
            </div>
            {detectHistory.length===0
              ?<Card title=""><Empty icon="📝" msg="No detections yet. Go to Detect tab and run a detection."/></Card>
              :<Card title={`${detectHistory.length} prediction${detectHistory.length!==1?"s":""} this session`}>
                <table style={S.table}>
                  <thead><tr>{["#","Time","Attack Type","Risk Score","Severity","Anomaly","Action"].map(h=><th key={h} style={S.th}>{h}</th>)}</tr></thead>
                  <tbody>{detectHistory.map((d,i)=>(
                    <tr key={i} style={{...S.tr,background:d.attack_type!=="BENIGN"&&d.severity==="High"?"rgba(248,113,113,0.05)":"transparent"}}>
                      <td style={{...S.td,color:T.muted}}>#{d.alert_id}</td>
                      <td style={{...S.td,fontSize:11}}>{fmt(d.ts||d.timestamp)}</td>
                      <td style={{...S.td,color:d.attack_type==="BENIGN"?T.green:T.red,fontWeight:600}}>{d.attack_type}</td>
                      <td style={S.td}>{d.risk_score?.toFixed(1)}</td>
                      <td style={S.td}>{sevBadge(d.severity)}</td>
                      <td style={{...S.td,color:d.is_anomaly?T.red:T.green}}>{d.is_anomaly?"Yes":"No"}</td>
                      <td style={S.td}>
                        <button onClick={()=>{setShapId(String(d.alert_id));loadShap(d.alert_id);setTab("shap");}}
                          style={{background:"rgba(129,140,248,0.1)",border:"1px solid rgba(129,140,248,0.3)",
                            borderRadius:6,color:T.indigo,cursor:"pointer",padding:"4px 10px",fontSize:11}}>
                          Explain
                        </button>
                      </td>
                    </tr>
                  ))}</tbody>
                </table>
              </Card>}
          </div>
        )}

        {/* ── SHAP ──────────────────────────────────────────────────────────── */}
        {tab==="shap"&&(
          <div style={{animation:"fadeIn 0.2s ease"}}>
            <h2 style={S.pageTitle}>SHAP Explainability</h2>
            <Card title="Select Alert to Explain">
              <div style={{display:"flex",gap:10,alignItems:"flex-end"}}>
                <div style={{flex:1}}>
                  <div style={{color:T.muted,fontSize:11,marginBottom:5,fontWeight:600,textTransform:"uppercase",letterSpacing:"0.5px"}}>Choose Alert</div>
                  <select value={shapId} onChange={e=>setShapId(e.target.value)} style={{...S.fsel,width:"100%"}}>
                    <option value="">— Select an alert —</option>
                    {alerts.slice(0,50).map(a=>(
                      <option key={a.id} value={a.id}>#{a.id} — {a.attack_type} — Risk:{a.risk_score?.toFixed(1)} — {fmtT(a.timestamp)}</option>
                    ))}
                  </select>
                </div>
                <button onClick={()=>loadShap(shapId)} disabled={!shapId||shapLoading}
                  style={{padding:"10px 20px",background:"linear-gradient(135deg,#0ea5e9,#6366f1)",
                    border:"none",borderRadius:8,color:"#fff",cursor:"pointer",fontSize:13,fontWeight:600,
                    opacity:!shapId?0.5:1}}>
                  {shapLoading?"⏳ Loading…":"Explain"}
                </button>
              </div>
              {shapErr&&<div style={{color:T.red,fontSize:12,marginTop:10}}>{shapErr}</div>}
            </Card>
            {shapLoading&&<Spinner/>}
            {shapData&&!shapLoading&&(
              <div>
                <div style={{background:"rgba(56,189,248,0.07)",border:`1px solid rgba(56,189,248,0.2)`,
                  borderRadius:10,padding:"12px 16px",marginBottom:14}}>
                  <div style={{color:T.blue,fontWeight:600,fontSize:12,marginBottom:4}}>💡 Plain English</div>
                  <div style={{color:T.text,fontSize:13}}>
                    {shapData.top_features?.length>0&&(()=>{
                      const top=shapData.top_features[0];
                      return `"${top.feature}" ${top.shap>=0?"increased":"decreased"} the likelihood of classifying as "${shapData.attack_type}" the most (SHAP: ${top.shap>0?"+":""}${top.shap?.toFixed(4)}).`;
                    })()}
                  </div>
                </div>
                <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:14,marginBottom:14}}>
                  <Card title="SHAP Feature Contributions" height={280}>
                    {shapBar?<Bar data={shapBar} options={cOpts({indexAxis:"y",plugins:{...cOpts().plugins,legend:{display:false}},
                      scales:{x:{ticks:{color:T.muted,font:{size:9}},grid:{color:"rgba(255,255,255,0.04)"},title:{display:true,text:"SHAP Value",color:T.muted,font:{size:9}}},
                              y:{ticks:{color:T.muted,font:{size:9}},grid:{color:"rgba(255,255,255,0.04)"}}}})}/>
                      :<Empty icon="📊" msg="No SHAP data"/>}
                  </Card>
                  <Card title="Feature Impact Bars">
                    {(shapData.top_features||[]).slice(0,8).map((f,i)=>{
                      const mx=Math.max(...shapData.top_features.map(x=>Math.abs(x.shap)));
                      const pct=mx>0?(Math.abs(f.shap)/mx)*100:0;
                      return <div key={i} style={{marginBottom:10}}>
                        <div style={{display:"flex",justifyContent:"space-between",marginBottom:3}}>
                          <span style={{color:T.sub,fontSize:11,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap",maxWidth:"72%"}}>{f.feature}</span>
                          <span style={{color:f.shap>=0?T.red:T.blue,fontSize:11,fontFamily:"monospace",fontWeight:600}}>{f.shap>=0?"+":""}{f.shap?.toFixed(4)}</span>
                        </div>
                        <div style={{height:7,background:T.bg,borderRadius:4,overflow:"hidden"}}>
                          <div style={{height:"100%",width:`${pct}%`,background:f.shap>=0?"rgba(248,113,113,0.8)":"rgba(56,189,248,0.8)",borderRadius:4}}/>
                        </div>
                      </div>;
                    })}
                  </Card>
                </div>
                <Card title="Contributions Table">
                  <table style={S.table}><thead><tr>{["#","Feature","SHAP Value","Direction"].map(h=><th key={h} style={S.th}>{h}</th>)}</tr></thead>
                  <tbody>{(shapData.top_features||[]).map((f,i)=>(
                    <tr key={f.feature} style={S.tr}>
                      <td style={{...S.td,color:T.muted}}>#{i+1}</td>
                      <td style={S.td}>{f.feature}</td>
                      <td style={{...S.td,color:f.shap>=0?T.red:T.blue,fontFamily:"monospace",fontWeight:600}}>{f.shap>=0?"+":""}{f.shap?.toFixed(5)}</td>
                      <td style={{...S.td,color:f.shap>=0?T.red:T.blue,fontSize:12}}>{f.shap>=0?"▲ Toward Attack":"▼ Toward Benign"}</td>
                    </tr>
                  ))}</tbody></table>
                </Card>
              </div>
            )}
            {!shapData&&!shapLoading&&<Card title=""><Empty icon="🔬" msg="Select an alert above and click Explain."/></Card>}
          </div>
        )}

        {/* ── CSV BULK UPLOAD ───────────────────────────────────────────────── */}
        {tab==="csv"&&(
          <div style={{animation:"fadeIn 0.2s ease"}}>
            <h2 style={S.pageTitle}>Bulk CSV Upload</h2>
            <Card title="📤 Upload CSV File">
              <p style={{color:T.muted,fontSize:13,marginBottom:16,lineHeight:1.6}}>
                Upload a CSV with insider-threat behaviour feature columns. The system will classify each row and return a full threat summary.
              </p>
              <div style={{border:`2px dashed ${T.border}`,borderRadius:10,padding:"28px 20px",textAlign:"center",marginBottom:16}}>
                <div style={{fontSize:32,marginBottom:8}}>📁</div>
                <input type="file" accept=".csv" id="csvInput" style={{display:"none"}}
                  onChange={async(e)=>{
                    const file=e.target.files[0]; if(!file) return;
                    setCsvLoading(true); setCsvSummary(null);
                    const fd=new FormData(); fd.append("file",file);
                    try{
                      const {data}=await API.post("/detect/upload-csv",fd);
                      const attacks=data.results.filter(r=>r.attack_type&&r.attack_type!=="BENIGN");
                      const normal=data.results.filter(r=>r.attack_type==="BENIGN");
                      const attackRate=data.processed>0?((attacks.length/data.processed)*100).toFixed(1):"0.0";
                      const byType={};
                      attacks.forEach(r=>{ byType[r.attack_type]=(byType[r.attack_type]||0)+1; });
                      setCsvSummary({processed:data.processed,attacks:attacks.length,normal:normal.length,
                        attackRate,byType,results:data.results,filename:file.name});
                      fetchAll();
                      showToast(`Processed ${data.processed} records from ${file.name}`);
                    } catch(err){ showToast(err.response?.data?.detail||"Upload failed","error"); }
                    finally{ setCsvLoading(false); e.target.value=""; }
                  }}/>
                <label htmlFor="csvInput" style={{cursor:"pointer",color:T.blue,fontWeight:600,fontSize:14}}>
                  Click to choose CSV file
                </label>
                <div style={{color:T.muted,fontSize:12,marginTop:6}}>Supports CICIDS 2017 format</div>
              </div>
              {csvLoading&&<Spinner/>}
            </Card>

            {csvSummary&&(
              <div>
                <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:12,marginBottom:14}}>
                  <StatCard icon="📦" label="Total Records" value={csvSummary.processed.toLocaleString()} accent={T.blue}/>
                  <StatCard icon="💣" label="Attacks Detected" value={csvSummary.attacks.toLocaleString()} accent={T.red}/>
                  <StatCard icon="✅" label="Normal Traffic" value={csvSummary.normal.toLocaleString()} accent={T.green}/>
                  <StatCard icon="📊" label="Attack Rate" value={`${csvSummary.attackRate}%`} accent={T.orange}/>
                </div>

                {Object.keys(csvSummary.byType).length>0&&(
                  <Card title="Attack Type Breakdown">
                    <div style={{display:"flex",flexWrap:"wrap",gap:10}}>
                      {Object.entries(csvSummary.byType).sort((a,b)=>b[1]-a[1]).map(([type,count],i)=>(
                        <div key={type} style={{background:`rgba(${PIE_COLORS[i%PIE_COLORS.length].replace("#","").match(/../g).map(h=>parseInt(h,16)).join(",")},0.12)`,
                          border:`1px solid ${PIE_COLORS[i%PIE_COLORS.length]}44`,borderRadius:8,padding:"8px 14px"}}>
                          <div style={{color:PIE_COLORS[i%PIE_COLORS.length],fontWeight:700,fontSize:18}}>{count}</div>
                          <div style={{color:T.muted,fontSize:11,marginTop:2}}>{type}</div>
                        </div>
                      ))}
                    </div>
                  </Card>
                )}

                <Card title={`Results — ${csvSummary.filename}`}
                  action={
                    <button onClick={()=>{
                      const header="Row,Attack Type,Risk Score,Severity,Is Anomaly";
                      const rows=csvSummary.results.map((r,i)=>`${i+1},${r.attack_type||"ERROR"},${r.risk_score?.toFixed(1)||""},${r.severity||""},${r.is_anomaly||""}`);
                      const blob=new Blob([[header,...rows].join("\n")],{type:"text/csv"});
                      const url=URL.createObjectURL(blob); const link=document.createElement("a");
                      link.href=url; link.download="bulk_results.csv"; link.click(); URL.revokeObjectURL(url);
                      showToast("Results exported");
                    }} style={{padding:"6px 14px",background:"rgba(74,222,128,0.1)",border:`1px solid ${T.green}`,
                      borderRadius:7,color:T.green,cursor:"pointer",fontSize:11,fontWeight:600}}>
                      ⬇ Export Results
                    </button>
                  }>
                  <table style={S.table}>
                    <thead><tr>{["Row","Attack Type","Risk Score","Severity","Anomaly"].map(h=><th key={h} style={S.th}>{h}</th>)}</tr></thead>
                    <tbody>{csvSummary.results.slice(0,20).map((r,i)=>(
                      <tr key={i} style={{...S.tr,background:r.attack_type!=="BENIGN"&&r.severity==="High"?"rgba(248,113,113,0.05)":"transparent"}}>
                        <td style={{...S.td,color:T.muted}}>{i+1}</td>
                        <td style={{...S.td,color:r.attack_type==="BENIGN"?T.green:T.red,fontWeight:600}}>{r.attack_type||"—"}</td>
                        <td style={S.td}>{r.risk_score?.toFixed(1)||"—"}</td>
                        <td style={S.td}>{r.severity?sevBadge(r.severity):"—"}</td>
                        <td style={{...S.td,color:r.is_anomaly?T.red:T.green}}>{r.is_anomaly!==undefined?(r.is_anomaly?"Yes":"No"):"—"}</td>
                      </tr>
                    ))}
                    {csvSummary.results.length>20&&<tr><td colSpan={5} style={{...S.td,color:T.muted,textAlign:"center",fontSize:11}}>… and {csvSummary.results.length-20} more rows — export CSV to see all</td></tr>}
                    </tbody>
                  </table>
                </Card>
              </div>
            )}
          </div>
        )}

        {/* ── LOGS ──────────────────────────────────────────────────────────── */}
        {tab==="logs"&&user?.role==="admin"&&(
          <div style={{animation:"fadeIn 0.2s ease"}}>
            <h2 style={S.pageTitle}>System Logs</h2>
            <Card title="">
              {loading?<Spinner/>:logs.length===0?<Empty icon="📋" msg="No logs yet."/>
                :<table style={S.table}><thead><tr>{["ID","Timestamp","User","Action","Detail"].map(h=><th key={h} style={S.th}>{h}</th>)}</tr></thead>
                <tbody>{logs.map(l=>(
                  <tr key={l.id} style={S.tr}>
                    <td style={{...S.td,color:T.muted}}>#{l.id}</td>
                    <td style={{...S.td,fontSize:11}}>{fmt(l.timestamp)}</td>
                    <td style={{...S.td,color:T.muted}}>{l.user_id||"—"}</td>
                    <td style={{...S.td,color:T.blue,fontWeight:600}}>{l.action}</td>
                    <td style={{...S.td,color:T.muted,fontSize:11}}>{l.detail||"—"}</td>
                  </tr>
                ))}</tbody></table>}
            </Card>
          </div>
        )}

      </main>
    </div>
  );
}
