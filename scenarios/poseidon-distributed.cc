#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/ndnSIM-module.h"

#include <ns3/point-to-point-module.h>

#include <boost/lexical_cast.hpp>

using namespace ns3;
using namespace ns3::ndn;
using namespace std;

#include "calculate-max-capacity.h"



uint32_t Run = 1;

void PrintTime (Time next, const string name)
{
  //cerr << " === " << name << " " << Simulator::Now ().ToDouble (Time::S) << "s" << endl;
  Simulator::Schedule (next, PrintTime, next, name);
}

int main (int argc, char**argv)
{
  string topology = "dfn";
  string prefix = "";
  string producerLocation = "gw";
  Time evilGap = Time::FromDouble (0.02, Time::MS);
  Time defaultRtt = Seconds (0.25);
  uint32_t badCount = 1;
  uint32_t goodCount = 0;
  string folder = "tmp";
  
  CommandLine cmd;
  cmd.AddValue ("topology", "Topology", topology);
  cmd.AddValue ("run", "Run", Run);
  cmd.AddValue ("algorithm", "DDoS mitigation algorithm", prefix);
  cmd.AddValue ("producer", "Producer location: gw or bb", producerLocation);
  cmd.AddValue ("badCount", "Number of bad guys", badCount);
  cmd.AddValue ("goodCount", "Number of good guys", goodCount);
  cmd.AddValue ("folder", "Folder where results will be placed", folder);
  cmd.AddValue ("defaultRtt", "Default RTT for BDP limits", defaultRtt);
  cmd.Parse (argc, argv);

  Config::SetGlobal ("RngRun", IntegerValue (Run));
  StackHelper helper;

  AppHelper evilAppHelper ("DdosAppPoseidon");
  evilAppHelper.SetAttribute ("Evil", BooleanValue (true));
  evilAppHelper.SetAttribute ("LifeTime", StringValue ("1s"));
  evilAppHelper.SetAttribute ("DataBasedLimits", BooleanValue (true));
  
  AppHelper goodAppHelper ("DdosAppPoseidon");
  goodAppHelper.SetAttribute ("LifeTime",  StringValue ("1s"));
  goodAppHelper.SetAttribute ("DataBasedLimits", BooleanValue (true));

  AppHelper ph ("ns3::ndn::Producer");
  ph.SetPrefix ("/good");
  ph.SetAttribute ("PayloadSize", StringValue("1100"));

  string name = prefix;
  name += "-topo-" + topology;
  name += "-evil-" + boost::lexical_cast<string> (badCount);
  name += "-good-" + boost::lexical_cast<string> (goodCount);
  name += "-producer-" + producerLocation;
  name += "-run-"  + boost::lexical_cast<string> (Run);
  
  string results_file = "results/" + folder + "/" + name + ".txt";
  string meta_file    = "results/" + folder + "/" + name + ".meta";
  string graph_dot_file    = "results/" + folder + "/" + name + ".dot";
  string graph_pdf_file    = "results/" + folder + "/" + name + ".pdf";

    AnnotatedTopologyReader topologyReader ("", 1.0);
    topologyReader.SetFileName ("topologies/" + topology + ".txt");
    topologyReader.Read ();

  if (prefix == "pushback-distributed")
    {
      //helper.EnableLimits (true, defaultRtt);  
      helper.SetForwardingStrategy ("ns3::ndn::fw::BestRoute::Stats::PoseidonPushbackDistributed");
    }
  else
    {
      cerr << "Invalid scenario prefix" << endl;
      return -1;
    }

  helper.Install (topologyReader.GetNodes ());

  topologyReader.ApplyOspfMetric ();
  
  GlobalRoutingHelper grouter;
  grouter.Install (topologyReader.GetNodes ());
  
  NodeContainer leaves;
  NodeContainer gw;
  NodeContainer bb;
  for_each (NodeList::Begin (), NodeList::End (), [&] (Ptr<Node> node) {
      if (Names::FindName (node).compare (0, 8, "Consumer")==0)
        {
          leaves.Add (node);
        }
      else if (Names::FindName (node).compare (0, 3, "gw-")==0)
        {
          gw.Add (node);
        }
      else if (Names::FindName (node).compare (0, 6, "Router")==0)
        {
          bb.Add (node);
        }
    });

  system (("mkdir -p \"results/" + folder + "\"").c_str ());
  ofstream os (meta_file.c_str(), ios_base::out | ios_base::trunc);
  
  os << "Total_numbef_of_nodes      " << NodeList::GetNNodes () << endl;
  os << "Total_number_of_leaf_nodes " << leaves.GetN () << endl;
  os << "Total_number_of_gw_nodes   " << gw.GetN () << endl;
  os << "Total_number_of_bb_nodes   " << bb.GetN () << endl;

  NodeContainer producerNodes;
  NodeContainer evilNodes;
  NodeContainer goodNodes;

  set< Ptr<Node> > producers;
  set< Ptr<Node> > evils;
  set< Ptr<Node> > angels;

  if (goodCount == 0)
    {
      goodCount = leaves.GetN () - badCount;
    }

  if (goodCount < 1)
    {
      NS_FATAL_ERROR ("Number of good guys should be at least 1");
      exit (1);
    }
  
  if (leaves.GetN () < goodCount+badCount)
    {
      NS_FATAL_ERROR ("Number of good and bad guys ("<< (goodCount+badCount) <<") cannot be less than number of leaves in the topology ("<< leaves.GetN () <<")");
      exit (1);
    }

  if (producerLocation == "gw")
    {
      if (gw.GetN () < 1)
        {
          NS_FATAL_ERROR ("Topology does not have gateway nodes that can serve as producers");
          exit (1);
        }
    }
  else if (producerLocation == "bb")
    {
      if (bb.GetN () < 1)
        {
          NS_FATAL_ERROR ("Topology does not have backbone nodes that can serve as producers");
          exit (1);
        }
    }
  else
    {
      NS_FATAL_ERROR ("--producer can be either 'gw' or 'bb'");
      exit (1);
    }
  
  os << "Number of evil nodes: " << badCount << endl;
  while (evils.size () < badCount)
    {
      UniformVariable randVar (0, leaves.GetN ());
      Ptr<Node> node = leaves.Get (randVar.GetValue ());
      string name = Names::FindName (node);
      
      if(name.substr(8,1) == "5" || name.substr(8,1) == "7" || name.substr(8,1) == "8" || name.substr(8,1) == "9")
      {  
	if (evils.find (node) != evils.end ())
        continue;
	evils.insert (node);
	Names::Rename (name, "evil-"+name);
      }
    }

  while (angels.size () < goodCount)
    {
      UniformVariable randVar (0, leaves.GetN ());
      Ptr<Node> node = leaves.Get (randVar.GetValue ());
      if (angels.find (node) != angels.end () ||
          evils.find (node) != evils.end ())
        continue;
      
      angels.insert (node);
      string name = Names::FindName (node);
      Names::Rename (name, "good-"+name);
    }

  while (producers.size () < 1)
    {
      Ptr<Node> node = 0;
      if (producerLocation == "gw")
        {
          UniformVariable randVar (0, gw.GetN ());
          node = gw.Get (randVar.GetValue ());
        }
      else if (producerLocation == "bb")
        {
          UniformVariable randVar (0, bb.GetN ());
          node = bb.Get (randVar.GetValue ());
        }
      
      producers.insert (node);
      string name = Names::FindName (node);
      Names::Rename (name, "producer-"+name);

      	if(Names::FindName (node) == "producer-producer-gw-root1")
	{
		string name = Names::FindName (node);
		string name1 = name.substr(9,17);
		Names::Rename (name, name1);
	}
    }
  
  auto assignNodes = [&os](NodeContainer &aset, const string &str) {
    return [&os, &aset, &str] (Ptr<Node> node)
    {
      string name = Names::FindName (node);
      cerr << name << endl;
      os << name << " ";
      aset.Add (node);
    };
  };
  os << endl;
  
  // a little bit of C++11 flavor, compile with -std=c++11 flag
  os << "Evil: ";
  std::for_each (evils.begin (), evils.end (), assignNodes (evilNodes, "Evil"));
  os << "\nGood: ";
  std::for_each (angels.begin (), angels.end (), assignNodes (goodNodes, "Good"));
  os << "\nProducers: ";
  std::for_each (producers.begin (), producers.end (), assignNodes (producerNodes, "Producers"));

  
  grouter.AddOrigins ("/", producerNodes);

  
  grouter.CalculateRoutes ();

  // verify topology RTT
  for (NodeList::Iterator node = NodeList::Begin (); node != NodeList::End (); node ++)
    {
      Ptr<Fib> fib = (*node)->GetObject<Fib> ();
      if (fib == 0 || fib->Begin () == 0) continue;

      if (2* fib->Begin ()->m_faces.begin ()->GetRealDelay ().ToDouble (Time::S) > defaultRtt.ToDouble (Time::S))
        {
          cout << "DefaultRTT is smaller that real RTT in the topology: " << 2*fib->Begin ()->m_faces.begin ()->GetRealDelay ().ToDouble (Time::S) << "s" << endl;
          os << "DefaultRTT is smaller that real RTT in the topology: " << 2*fib->Begin ()->m_faces.begin ()->GetRealDelay ().ToDouble (Time::S) << "s" << endl;
        }
    }

  double maxNonCongestionShare = 0.8 * calculateNonCongestionFlows (goodNodes, producerNodes);
  os << "maxNonCongestionShare   " << maxNonCongestionShare << endl;

  saveActualGraph (graph_dot_file, NodeContainer (goodNodes, evilNodes));
  system (("twopi -Tpdf \"" + graph_dot_file + "\" > \"" + graph_pdf_file + "\"").c_str ());
  cout << "Write effective topology graph to: " << graph_pdf_file << endl;
  cout << "Max non-congestion share:   " << maxNonCongestionShare << endl;

  // exit (1);
    
  for (NodeContainer::Iterator node = goodNodes.Begin (); node != goodNodes.End (); node++)
    {
      ApplicationContainer goodApp;
      goodAppHelper.SetPrefix ("/good/"+Names::FindName (*node));
      goodAppHelper.SetAttribute ("AvgGap", TimeValue (Seconds (1.100 / maxNonCongestionShare)));
      goodApp.Add (goodAppHelper.Install (*node));
      UniformVariable rand (0, 1);
      goodApp.Start (Seconds (0.0) + Time::FromDouble (rand.GetValue (), Time::S));
    }
  
  for (NodeContainer::Iterator node = evilNodes.Begin (); node != evilNodes.End (); node++)
    {
      ApplicationContainer evilApp;
      evilAppHelper.SetPrefix ("/evil/"+Names::FindName (*node));
      evilAppHelper.SetAttribute ("AvgGap", TimeValue (Seconds (0.001)));
      evilApp.Add (evilAppHelper.Install (*node));
      UniformVariable rand (0, 1);
      evilApp.Start (Seconds (0.0) + Time::FromDouble (rand.GetValue (), Time::MS));
      evilApp.Stop  (Seconds (900.0) + Time::FromDouble (rand.GetValue (), Time::MS));  
    }
  
  ph.Install (producerNodes);
  
  L3RateTracer::InstallAll (results_file, Seconds (1.0));

  //Simulator::Schedule (Seconds (10.0), PrintTime, Seconds (10.0), name);

  Simulator::Stop (Seconds (900.0));
  Simulator::Run ();
  Simulator::Destroy ();
  L3RateTracer::Destroy ();

  cerr << "Archiving to: " << results_file << ".bz2" << endl;
  system (("rm -f \"" + results_file + ".bz2" + "\"").c_str() );
  system (("bzip2 \"" + results_file + "\"").c_str() );
  
  return 0;
}
