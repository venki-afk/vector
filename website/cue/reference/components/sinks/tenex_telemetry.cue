package metadata

components: sinks: tenex_telemetry: {
	title: "TENEX Telemetry"
	classes: {
		delivery:      "at_least_once"
		development:   "beta"
		egress_method: "stream"
		service_providers: ["TENEX"]
		stateful: false
	}
	features: {
		acknowledgements: true
		auto_generated:   true
		healthcheck: enabled: false
		send: {
			compression: enabled: false
			encoding: enabled:    false
			proxy: enabled:       true
			request: {
				enabled: true
				headers: false
			}
			tls: {
				enabled:                true
				can_verify_certificate: true
				can_verify_hostname:    true
				enabled_default:        true
				enabled_by_scheme:      true
			}
			to: {
				service: services.tenex_telemetry
				interface: socket: {
					direction: "outgoing"
					protocols: ["http"]
					ssl: "required"
				}
			}
		}
	}
	configuration: generated.components.sinks.tenex_telemetry.configuration
	input: {
		logs:    true
		metrics: null
		traces:  false
	}
	support: {
		requirements: []
		warnings: []
		notices: ["This sink requires a Vector build that includes the TENEX Telemetry component."]
	}
	how_it_works: {
		delivery: {
			title: "Delivery and replay"
			body: """
				Each log is sent as one JSON object with a stable event delivery ID as
				Idempotency-Key. Assign that ID before the sink disk buffer and do not
				change the payload when replaying it. The sink does not batch requests.

				A valid intake receipt confirms durable raw acceptance, not successful
				normalization, indexing, or search availability. Check the destination's
				processing health separately. Delivery is at least once; this component
				does not promise exactly-once processing of replayed source data.
				"""
		}
		security: {
			title: "Authentication"
			body: """
				Use a scoped intake API key supplied by your deployment secret backend.
				The intake service derives the tenant, source, and stream from that key.
				Use separate sink instances and credentials for separate intake scopes.
				HTTPS is required outside loopback development. Redirects are not followed.
				The sink performs configuration validation only at startup; there is no
				remote healthcheck because intake has no side-effect-free check endpoint.
				"""
		}
	}
}
