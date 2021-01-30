package internal

import (
	"context"
	"log"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
)

// PublicIpsResponse Response returned to the lambda runtime that wraps the error but still reports the error.
type PublicIpsResponse struct {
	Addresses   []string `json:"address,omitempty"`
	CidrsAdded  []string `json:"cidrs_added,omitempty"`
	CidrsRemove []string `json:"cidrs_removed,omitempty"`
}

const SOURCE = "source"

var (
	// Info Logger
	Info *log.Logger

	securityGroupID string
	svc             *ec2.EC2
)

func init() {

	Info = log.New(os.Stdout,
		"[INFO]: ",
		log.Ldate|log.Ltime|log.Lshortfile)

	securityGroupID = os.Getenv("SECURITY_GROUP_ID")
	svc = ec2.New(session.Must(session.NewSession()))
}

//goland:noinspection GoUnusedExportedFunction
func HandleRequest(ctx context.Context) (PublicIpsResponse, error) {

	sourceCidrs, securityGroupIngressCidrs := extract(securityGroupID, ctx.Value(SOURCE).(func() []string))
	cidrsToAdd, cidrsToRemove := transform(sourceCidrs, securityGroupIngressCidrs)
	load(securityGroupID, cidrsToAdd, cidrsToRemove)

	return PublicIpsResponse{
		Addresses:   sourceCidrs,
		CidrsAdded:  cidrsToAdd,
		CidrsRemove: cidrsToRemove,
	}, nil
}

func extract(securityGroupID string, source func() []string) ([]string, []string) {
	var securityGroupIngress []string

	ipv4IPs := source()

	dsgi := &ec2.DescribeSecurityGroupsInput{
		GroupIds: []*string{
			aws.String(securityGroupID),
		},
	}

	dsgo, dsgoErr := svc.DescribeSecurityGroups(dsgi)
	if dsgoErr != nil || dsgo.SecurityGroups == nil || len(dsgo.SecurityGroups) != 1 {
		if dsgoErr != nil {
			panic(dsgoErr)
		}
	}

	if len(dsgo.SecurityGroups[0].IpPermissions) != 0 {
		for _, value := range dsgo.SecurityGroups[0].IpPermissions[0].IpRanges {
			securityGroupIngress = append(securityGroupIngress, *value.CidrIp)
		}
	}

	return ipv4IPs, securityGroupIngress
}

// To determine what the security group ingress must be set too we need to run two joins.
// Join A: Left Join - Find what is in fastlyCidrs but not in securityGroupIngressCidrs and add them
// Join B: Right Join - Find what is in securityGroupIngressCidrs but not in fastlyCidrs and remove them
func transform(fastlyCidrs []string, securityGroupIngressCidrs []string) ([]string, []string) {
	var cidrsToAdd []string
	var cidrsToRemove []string

	// Join A
	for _, fastlyCidr := range fastlyCidrs {
		if !contains(fastlyCidr, securityGroupIngressCidrs) {
			cidrsToAdd = append(cidrsToAdd, fastlyCidr)
		}
	}

	// Join B
	for _, securityGroupIngressCidr := range securityGroupIngressCidrs {
		if !contains(securityGroupIngressCidr, fastlyCidrs) {
			cidrsToRemove = append(cidrsToRemove, securityGroupIngressCidr)
		}
	}

	return cidrsToAdd, cidrsToRemove
}

func load(securityGroupID string, cidrsToAdd []string, cidrsToRemove []string) {

	if os.Getenv("LOAD") == "true" {
		if len(cidrsToAdd) != 0 {
			var ipPermissions []*ec2.IpPermission
			for _, cidr := range cidrsToAdd {
				var ipRanges []*ec2.IpRange
				ipRange := ec2.IpRange{
					CidrIp: aws.String(cidr),
				}

				ipRanges = append(ipRanges, &ipRange)
				ipPermission := ec2.IpPermission{
					IpProtocol: aws.String("-1"),
					IpRanges:   ipRanges,
				}

				Info.Printf("Authorizing IpPermission: %v", ipPermission)
				ipPermissions = append(ipPermissions, &ipPermission)
			}

			asgii := &ec2.AuthorizeSecurityGroupIngressInput{
				GroupId:       aws.String(securityGroupID),
				IpPermissions: ipPermissions,
			}

			_, asgiErr := svc.AuthorizeSecurityGroupIngress(asgii)

			if asgiErr != nil {
				panic(asgiErr)
			}
		}

		if len(cidrsToRemove) != 0 {
			var ipPermissions []*ec2.IpPermission
			for _, cidr := range cidrsToRemove {
				var ipRanges []*ec2.IpRange
				ipRange := ec2.IpRange{
					CidrIp: aws.String(cidr),
				}

				ipRanges = append(ipRanges, &ipRange)
				ipPermission := ec2.IpPermission{
					FromPort:   aws.Int64(0),
					ToPort:     aws.Int64(65535),
					IpProtocol: aws.String("tcp"),
					IpRanges:   ipRanges,
				}

				Info.Printf("Revoking IpPermission: %v", ipPermission)
				ipPermissions = append(ipPermissions, &ipPermission)
			}

			rsgii := &ec2.RevokeSecurityGroupIngressInput{
				GroupId:       aws.String(securityGroupID),
				IpPermissions: ipPermissions,
			}

			_, rsgiErr := svc.RevokeSecurityGroupIngress(rsgii)
			if rsgiErr != nil {
				panic(rsgiErr)
			}
		}
	}
}

func contains(cidr string, cidrs []string) bool {
	for _, value := range cidrs {
		if strings.Compare(value, cidr) == 0 {
			return true
		}
	}

	return false
}
