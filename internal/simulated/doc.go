// Package simulated is the development build's simulated sign-in: under the skipAuth
// build tag the Azure and Google methods contact no provider and take who signed in,
// and which roles they hold, from the environment. The package holds the one rule both
// methods read the environment by; it has no code outside that build tag.
package simulated
